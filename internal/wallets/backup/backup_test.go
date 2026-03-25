package backup_test

import (
	"crypto/ecdsa"
	"testing"

	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/internal/wallets/backup"
	"github.com/flare-foundation/tee-node/pkg/utils"
	"github.com/flare-foundation/tee-node/pkg/wallets"
	pbackup "github.com/flare-foundation/tee-node/pkg/wallets/backup"
	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

var mockWalletID = common.HexToHash("0xabcdef")
var mockKeyID = uint64(1)

func TestBackupAndRecover(t *testing.T) {
	testNode, _, _ := testutils.Setup(t)

	idPair := wallets.KeyIDPair{WalletID: mockWalletID, KeyID: mockKeyID}
	sk, err := crypto.GenerateKey()
	assert.NoError(t, err)

	// Generate admin and provider public keys
	adminKeys, providerKeys := generateTestKeys(t, 3, 2)

	adminPubKeys := privateKeysToPublicKeys(t, adminKeys)
	providerPubKeys := privateKeysToPublicKeys(t, providerKeys)

	weights := []uint16{7, 20}
	normalizationParam := 27
	dataProvidersBackupThreshold := uint64(22)
	adminsThreshold := uint64(2)
	rewardEpochID := uint32(100)

	baseWallet := &wallets.Wallet{
		WalletID:    idPair.WalletID,
		KeyID:       idPair.KeyID,
		PrivateKey:  common.BigToHash(sk.D).Bytes(),
		KeyType:     wallets.XRPType,
		SigningAlgo: wallets.XRPSignAlgo,
		Restored:    false,

		AdminPublicKeys:    adminPubKeys,
		AdminsThreshold:    adminsThreshold,
		Cosigners:          []common.Address{common.HexToAddress("aa")},
		CosignersThreshold: 1,

		Status: &wallets.WalletStatus{},

		SettingsVersion: common.Hash{},
		Settings:        hexutil.Bytes{},
	}

	t.Run("Unsupported signing algorithm should fail", func(t *testing.T) {
		unsupportedAlgoWallet := *baseWallet
		unsupportedAlgoWallet.SigningAlgo = utils.ToHash("BLS-12-381")
		_, err = backup.BackupWallet(&unsupportedAlgoWallet, providerPubKeys, weights, rewardEpochID, testNode.TeeID(), uint16(normalizationParam), dataProvidersBackupThreshold)
		assert.Error(t, err)
	})

	algoTests := []struct {
		name        string
		keyType     common.Hash
		signingAlgo common.Hash
	}{
		{"XRP", wallets.XRPType, wallets.XRPSignAlgo},
		{"EVM", wallets.EVMType, wallets.EVMSignAlgo},
		{"VRF", wallets.EVMType, wallets.VRFAlgo},
	}

	for _, tc := range algoTests {
		t.Run("Backup and recover wallet should succeed ("+tc.name+")", func(t *testing.T) {
			givenWallet := *baseWallet
			givenWallet.KeyType = tc.keyType
			givenWallet.SigningAlgo = tc.signingAlgo

			// Backup the wallet
			walletBackup, err := backup.BackupWallet(&givenWallet, providerPubKeys, weights, rewardEpochID, testNode.TeeID(), uint16(normalizationParam), dataProvidersBackupThreshold)
			assert.NoError(t, err)
			assert.NotNil(t, walletBackup)

			// Add TEE signature (normally done by the TEE processor)
			backupHash, err := walletBackup.HashForSigning()
			assert.NoError(t, err)
			walletBackup.TEESignature, err = testNode.Sign(backupHash[:])
			assert.NoError(t, err)

			err = walletBackup.Check()
			assert.NoError(t, err)

			// Decrypt admin and provider shares
			adminKeyShares, providerKeyShares := decryptAllShares(t, walletBackup.AdminEncryptedParts, walletBackup.ProviderEncryptedParts, adminKeys, providerKeys)

			// Recover the wallet
			recoveredWallet, err := backup.RecoverWallet(
				append(adminKeyShares, providerKeyShares...),
				&walletBackup.WalletBackupMetaData,
			)
			assert.NoError(t, err)
			givenWallet.Restored = true
			assert.Equal(t, &givenWallet, recoveredWallet)
		})
	}
}

func TestSplitAndEncrypt(t *testing.T) {
	// Generate a private key
	privateKey, err := crypto.GenerateKey()
	assert.NoError(t, err)

	// Generate public keys for encryption
	keys, _ := generateTestKeys(t, 2, 0)
	encryptionPubKeys := privateKeysToPublicKeys(t, keys)

	signer := &wallets.Wallet{PrivateKey: common.BigToHash(privateKey.D).Bytes(), SigningAlgo: wallets.EVMSignAlgo}

	// Split and encrypt the key
	encryptedShares, err := backup.SplitAndEncrypt(privateKey, encryptionPubKeys, 2, utils.ConstantSlice(uint16(1), 2), wallets.WalletBackupID{}, signer, false)
	assert.NoError(t, err)
	assert.NotNil(t, encryptedShares)
}

func TestRecoverWithMissingShares(t *testing.T) {
	testNode, _, _ := testutils.Setup(t)

	idPair := wallets.KeyIDPair{WalletID: mockWalletID, KeyID: mockKeyID}
	sk, err := crypto.GenerateKey()
	assert.NoError(t, err)

	// Generate admin and provider public keys
	adminKeys, providerKeys := generateTestKeys(t, 3, 2)
	adminPubKeys := privateKeysToPublicKeys(t, adminKeys)
	providerPubKeys := privateKeysToPublicKeys(t, providerKeys)

	weights := []uint16{7, 20}
	normalizationParam := 27
	dataProvidersBackupThreshold := uint64(22)

	adminsThreshold := uint64(2)

	givenWallet := &wallets.Wallet{
		WalletID:    idPair.WalletID,
		KeyID:       idPair.KeyID,
		PrivateKey:  common.BigToHash(sk.D).Bytes(),
		KeyType:     wallets.XRPType,
		SigningAlgo: wallets.XRPSignAlgo,
		Restored:    false,

		AdminPublicKeys:    adminPubKeys,
		AdminsThreshold:    adminsThreshold,
		Cosigners:          []common.Address{common.HexToAddress("aa")},
		CosignersThreshold: 1,

		Status: &wallets.WalletStatus{},

		SettingsVersion: common.Hash{},
		Settings:        hexutil.Bytes{},
	}

	rewardEpochID := uint32(100)

	// Backup the wallet
	walletBackup, err := backup.BackupWallet(givenWallet, providerPubKeys, weights, rewardEpochID, testNode.TeeID(), uint16(normalizationParam), dataProvidersBackupThreshold)
	assert.NoError(t, err)
	assert.NotNil(t, walletBackup)

	// Add TEE signature (normally done by the TEE processor)
	backupHash, err := walletBackup.HashForSigning()
	assert.NoError(t, err)
	walletBackup.TEESignature, err = testNode.Sign(backupHash[:])
	assert.NoError(t, err)

	err = walletBackup.Check()
	assert.NoError(t, err)

	// Decrypt admin and provider shares
	adminKeyShares, providerKeyShares := decryptAllShares(t, walletBackup.AdminEncryptedParts, walletBackup.ProviderEncryptedParts, adminKeys, providerKeys)

	t.Run("Recovery with missing provider share should fail", func(t *testing.T) {
		recoveredWallet, err := backup.RecoverWallet(
			append(adminKeyShares, providerKeyShares[:1]...),
			&walletBackup.WalletBackupMetaData,
		)
		assert.Error(t, err)
		require.Nil(t, recoveredWallet)
	})

	t.Run("Recovery with missing admin share should fail", func(t *testing.T) {
		recoveredWallet, err := backup.RecoverWallet(
			append(adminKeyShares[:1], providerKeyShares...),
			&walletBackup.WalletBackupMetaData,
		)
		assert.Error(t, err)
		require.Nil(t, recoveredWallet)
	})

	t.Run("Recovery without admin shares should fail", func(t *testing.T) {
		recoveredWallet, err := backup.RecoverWallet(
			providerKeyShares,
			&walletBackup.WalletBackupMetaData,
		)
		assert.Error(t, err)
		require.Nil(t, recoveredWallet)
	})

	t.Run("Recovery without provider shares should fail", func(t *testing.T) {
		recoveredWallet, err := backup.RecoverWallet(
			adminKeyShares,
			&walletBackup.WalletBackupMetaData,
		)
		assert.Error(t, err)
		require.Nil(t, recoveredWallet)
	})

	t.Run("Recovery with mismatched PartialBackupID should fail", func(t *testing.T) {
		invalidAdminShare := *adminKeyShares[0]
		invalidAdminShare.PublicKey[0] ^= 0xFF

		mixedShares := []*pbackup.KeySplit{
			&invalidAdminShare,
			adminKeyShares[1],
			providerKeyShares[0],
			providerKeyShares[1],
		}

		recoveredWallet, err := backup.RecoverWallet(
			mixedShares,
			&walletBackup.WalletBackupMetaData,
		)
		assert.Error(t, err)
		require.Nil(t, recoveredWallet)
	})

	t.Run("Recovery with wrong admin's OwnerPublicKey should fail", func(t *testing.T) {
		invalidAdminShare := *adminKeyShares[0]

		invalidPk := adminKeyShares[0].OwnerPublicKey
		for i := range invalidPk.X {
			invalidPk.X[i] ^= 0xFF
		}
		invalidAdminShare.OwnerPublicKey = invalidPk
		invalidAdminShare.IsAdmin = true

		mixedShares := []*pbackup.KeySplit{
			&invalidAdminShare,
			adminKeyShares[1],
			providerKeyShares[0],
			providerKeyShares[1],
		}

		recoveredWallet, err := backup.RecoverWallet(
			mixedShares,
			&walletBackup.WalletBackupMetaData,
		)
		assert.Error(t, err)
		require.Nil(t, recoveredWallet)
	})

	t.Run("Recovery with mismatched WalletBackupID should fail", func(t *testing.T) {
		invalidBackupMetaData := walletBackup.WalletBackupMetaData
		invalidBackupMetaData.WalletID[0] ^= 0xFF

		recoveredWallet, err := backup.RecoverWallet(
			append(adminKeyShares, providerKeyShares...),
			&invalidBackupMetaData,
		)
		assert.Error(t, err)
		require.Nil(t, recoveredWallet)
	})

	t.Run("Recovery with adminThreshold <= 0 should fail", func(t *testing.T) {
		invalidMeta := walletBackup.WalletBackupMetaData
		invalidMeta.AdminsThreshold = 0

		recoveredWallet, err := backup.RecoverWallet(
			append(adminKeyShares, providerKeyShares...),
			&invalidMeta,
		)
		assert.Error(t, err)
		require.Nil(t, recoveredWallet)
	})

	t.Run("Recovery with providerThreshold <= 0 should fail", func(t *testing.T) {
		invalidMeta := walletBackup.WalletBackupMetaData
		invalidMeta.ProvidersThreshold = 0

		recoveredWallet, err := backup.RecoverWallet(
			append(adminKeyShares, providerKeyShares...),
			&invalidMeta,
		)
		assert.Error(t, err)
		require.Nil(t, recoveredWallet)
	})
}

func generateTestKeys(t *testing.T, numAdmins int, numProviders int) ([]*ecdsa.PrivateKey, []*ecdsa.PrivateKey) {
	t.Helper()
	adminKeys := make([]*ecdsa.PrivateKey, numAdmins)
	providerKeys := make([]*ecdsa.PrivateKey, numProviders)
	var err error
	for i := range numAdmins {
		adminKeys[i], err = crypto.GenerateKey()
		assert.NoError(t, err)
	}

	for i := range numProviders {
		providerKeys[i], err = crypto.GenerateKey()
		assert.NoError(t, err)
	}

	return adminKeys, providerKeys
}

func privateKeysToPublicKeys(t *testing.T, privateKeys []*ecdsa.PrivateKey) []*ecdsa.PublicKey {
	t.Helper()
	publicKeys := make([]*ecdsa.PublicKey, len(privateKeys))
	for i := range privateKeys {
		publicKeys[i] = &privateKeys[i].PublicKey
	}
	return publicKeys
}

func decryptAllShares(t *testing.T, adminEncryptedParts, providerEncryptedParts *pbackup.EncryptedShares, adminKeys, providerKeys []*ecdsa.PrivateKey) ([]*pbackup.KeySplit, []*pbackup.KeySplit) {
	t.Helper()
	adminKeyShares := make([]*pbackup.KeySplit, len(adminKeys))
	providerKeyShares := make([]*pbackup.KeySplit, len(providerKeys))
	for i, k := range adminKeys {
		share, err := pbackup.DecryptSplit(adminEncryptedParts.Splits[i], k)
		assert.NoError(t, err)
		adminKeyShares[i] = share
	}

	for i, k := range providerKeys {
		share, err := pbackup.DecryptSplit(providerEncryptedParts.Splits[i], k)
		assert.NoError(t, err)
		providerKeyShares[i] = share
	}
	return adminKeyShares, providerKeyShares
}
