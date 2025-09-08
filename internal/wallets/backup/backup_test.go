package backup_test

import (
	"crypto/ecdsa"
	"testing"

	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/internal/wallets/backup"
	"github.com/flare-foundation/tee-node/pkg/utils"
	"github.com/flare-foundation/tee-node/pkg/wallets"
	pbackup "github.com/flare-foundation/tee-node/pkg/wallets/backup"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/signing/secp256k1"
	"github.com/stretchr/testify/assert"
)

var mockWalletId = common.HexToHash("0xabcdef")
var mockKeyId = uint64(1)

func TestBackupAndRecover(t *testing.T) {
	testNode, _, _ := testutils.Setup(t)

	idPair := wallets.KeyIDPair{WalletID: mockWalletId, KeyID: mockKeyId}
	sk, err := crypto.GenerateKey()
	assert.NoError(t, err)

	xrpAddress := secp256k1.PrvToAddress(sk)
	assert.NoError(t, err)

	// Generate admin and provider public keys
	adminKey1, err := crypto.GenerateKey()
	assert.NoError(t, err)
	adminKey2, err := crypto.GenerateKey()
	assert.NoError(t, err)
	adminKey3, err := crypto.GenerateKey()
	assert.NoError(t, err)
	providerKey1, err := crypto.GenerateKey()
	assert.NoError(t, err)
	providerKey2, err := crypto.GenerateKey()
	assert.NoError(t, err)

	providerPubKeys := []*ecdsa.PublicKey{&providerKey1.PublicKey, &providerKey2.PublicKey}
	weights := []uint16{7, 20}
	normalizationParam := 27
	dataProvidersBackupThreshold := uint64(22)

	adminPubKeys := []*ecdsa.PublicKey{&adminKey1.PublicKey, &adminKey2.PublicKey, &adminKey3.PublicKey}
	adminsThreshold := uint64(2)

	givenWallet := &wallets.Wallet{
		WalletID:        idPair.WalletID,
		KeyID:           idPair.KeyID,
		PrivateKey:      sk,
		Address:         crypto.PubkeyToAddress(sk.PublicKey),
		ExternalAddress: xrpAddress,
		Restored:        false,

		AdminPublicKeys:    adminPubKeys,
		AdminsThreshold:    adminsThreshold,
		Cosigners:          []common.Address{common.HexToAddress("aa")},
		CosignersThreshold: 1,
		OpType:             op.XRP.Hash(),
		OpTypeConstants:    []byte("bla"),

		Status: &wallets.WalletStatus{},
	}

	rewardEpochId := uint32(100)

	// Backup the wallet
	walletBackup, err := backup.BackupWallet(givenWallet, providerPubKeys, weights, rewardEpochId, testNode.TeeID(), uint16(normalizationParam), dataProvidersBackupThreshold)
	assert.NoError(t, err)
	assert.NotNil(t, walletBackup)
	err = walletBackup.Check()
	assert.NoError(t, err)

	// Decrypt admin and provider shares
	adminShare1, err := pbackup.DecryptSplit(walletBackup.AdminEncryptedParts.Splits[0], adminKey1)
	assert.NoError(t, err)
	adminShare2, err := pbackup.DecryptSplit(walletBackup.AdminEncryptedParts.Splits[1], adminKey2)
	assert.NoError(t, err)
	providerShare1, err := pbackup.DecryptSplit(walletBackup.ProviderEncryptedParts.Splits[0], providerKey1)
	assert.NoError(t, err)
	providerShare2, err := pbackup.DecryptSplit(walletBackup.ProviderEncryptedParts.Splits[1], providerKey2)
	assert.NoError(t, err)

	adminKeyShares := []*pbackup.KeySplit{adminShare1, adminShare2}
	providerKeyShares := []*pbackup.KeySplit{providerShare1, providerShare2}

	// Recover the wallet
	recoveredWallet, err := backup.RecoverWallet(
		append(adminKeyShares, providerKeyShares...),
		&walletBackup.WalletBackupMetaData,
	)
	assert.NoError(t, err)
	givenWallet.Restored = true
	assert.Equal(t, givenWallet, recoveredWallet)
}

func TestSplitAndEncrypt(t *testing.T) {
	// Generate a private key
	privateKey, err := crypto.GenerateKey()
	assert.NoError(t, err)

	// Generate public keys for encryption
	pubKey1, err := crypto.GenerateKey()
	assert.NoError(t, err)
	pubKey2, err := crypto.GenerateKey()
	assert.NoError(t, err)

	encryptionPubKeys := []*ecdsa.PublicKey{&pubKey1.PublicKey, &pubKey2.PublicKey}

	// Split and encrypt the key
	encryptedShares, err := backup.SplitAndEncrypt(privateKey, encryptionPubKeys, 2, utils.ConstantSlice(uint16(1), 2), wallets.WalletBackupID{}, privateKey, false)
	assert.NoError(t, err)
	assert.NotNil(t, encryptedShares)
}
