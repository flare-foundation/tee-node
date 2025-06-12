package wallets

import (
	"crypto/ecdsa"
	"tee-node/pkg/tee/node"
	"tee-node/pkg/tee/settings"
	"tee-node/pkg/tee/utils"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

var mockWalletId = common.HexToHash("0xabcdef")
var mockKeyId = uint64(1)

func TestBackupAndRecover(t *testing.T) {
	err := node.InitNode()
	assert.NoError(t, err)

	idPair := WalletKeyIdPair{mockWalletId, mockKeyId}
	sk, err := utils.GenerateEthereumPrivateKey()
	assert.NoError(t, err)

	sec1PubKey := utils.SerializeCompressed(&sk.PublicKey)
	xrpAddress, err := utils.GetXrpAddressFromPubkey(sec1PubKey)
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

	providersPubKeys := []*ecdsa.PublicKey{&providerKey1.PublicKey, &providerKey2.PublicKey}
	weights := []uint16{7, 20}
	settings.NormalizationConstant = 27
	settings.DataProvidersBackupThreshold = uint64(22)

	adminsPubKeys := []*ecdsa.PublicKey{&adminKey1.PublicKey, &adminKey2.PublicKey, &adminKey3.PublicKey}
	adminsThreshold := uint64(2)

	wallet := &Wallet{WalletId: idPair.WalletId, KeyId: idPair.KeyId, PrivateKey: sk,
		Address: crypto.PubkeyToAddress(sk.PublicKey), XrpAddress: xrpAddress,
		AdminsPublicKeys: adminsPubKeys, AdminsThreshold: adminsThreshold,
		Cosigners:          []common.Address{common.HexToAddress("aa")},
		CosignersThreshold: 1,
		OpType:             [32]byte{12},
		OpTypeConstants:    []byte("bla"),
	}

	rewardEpochId := uint32(100)

	// Backup the wallet
	walletBackup, err := BackupWallet(wallet, providersPubKeys, weights, rewardEpochId, node.GetTeeId())
	assert.NoError(t, err)
	assert.NotNil(t, walletBackup)

	// Decrypt admin and provider shares
	adminShare1, err := DecryptSplit(walletBackup.AdminEncryptedParts.Splits[0], adminKey1)
	assert.NoError(t, err)
	adminShare2, err := DecryptSplit(walletBackup.AdminEncryptedParts.Splits[1], adminKey2)
	assert.NoError(t, err)
	providerShare1, err := DecryptSplit(walletBackup.ProvidersEncryptedParts.Splits[0], providerKey1)
	assert.NoError(t, err)
	providerShare2, err := DecryptSplit(walletBackup.ProvidersEncryptedParts.Splits[1], providerKey2)
	assert.NoError(t, err)

	adminsKeyShares := []*KeySplit{adminShare1, adminShare2}
	providersKeyShares := []*KeySplit{providerShare1, providerShare2}

	// Recover the wallet
	recoveredWallet, err := RecoverWallet(
		append(adminsKeyShares, providersKeyShares...),
		walletBackup.WalletBackupMetaData,
	)
	assert.NoError(t, err)
	wallet.Restored = true
	assert.Equal(t, wallet, recoveredWallet)
}

func TestSplitAndEncrypt(t *testing.T) {
	err := node.InitNode()
	assert.NoError(t, err)
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
	encryptedShares, err := SplitAndEncrypt(privateKey, encryptionPubKeys, 2, utils.ConstantSlice(1, 2), WalletBackupId{}, privateKey, false)
	assert.NoError(t, err)
	assert.NotNil(t, encryptedShares)
}
