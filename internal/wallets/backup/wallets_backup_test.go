package backup

import (
	"crypto/ecdsa"
	"testing"

	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/internal/wallets"
	"github.com/flare-foundation/tee-node/pkg/backup"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

var mockWalletId = common.HexToHash("0xabcdef")
var mockKeyId = uint64(1)

func TestBackupAndRecover(t *testing.T) {
	err := node.InitNode(types.State{})
	assert.NoError(t, err)

	idPair := types.WalletKeyIdPair{WalletId: mockWalletId, KeyId: mockKeyId}
	sk, err := utils.GenerateEthereumPrivateKey()
	assert.NoError(t, err)

	sec1PubKey := utils.SerializeCompressed(&sk.PublicKey)
	xrpAddress, err := utils.XRPLAddressFromSecp256k1PubKey(sec1PubKey)
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
	settings.NormalizationConstant = 27
	settings.DataProvidersBackupThreshold = uint64(22)

	adminPubKeys := []*ecdsa.PublicKey{&adminKey1.PublicKey, &adminKey2.PublicKey, &adminKey3.PublicKey}
	adminsThreshold := uint64(2)

	givenWallet := &wallets.Wallet{
		WalletId:   idPair.WalletId,
		KeyId:      idPair.KeyId,
		PrivateKey: sk,
		Address:    crypto.PubkeyToAddress(sk.PublicKey),
		XrpAddress: xrpAddress,
		Restored:   false,

		AdminPublicKeys:    adminPubKeys,
		AdminsThreshold:    adminsThreshold,
		Cosigners:          []common.Address{common.HexToAddress("aa")},
		CosignersThreshold: 1,
		OpType:             [32]byte{12},
		OpTypeConstants:    []byte("bla"),

		Status: &wallets.WalletStatus{},
	}

	rewardEpochId := uint32(100)

	// Backup the wallet
	walletBackup, err := BackupWallet(givenWallet, providerPubKeys, weights, rewardEpochId, node.GetTeeId())
	assert.NoError(t, err)
	assert.NotNil(t, walletBackup)
	err = walletBackup.Check()
	assert.NoError(t, err)

	// Decrypt admin and provider shares
	adminShare1, err := backup.DecryptSplit(walletBackup.AdminEncryptedParts.Splits[0], adminKey1)
	assert.NoError(t, err)
	adminShare2, err := backup.DecryptSplit(walletBackup.AdminEncryptedParts.Splits[1], adminKey2)
	assert.NoError(t, err)
	providerShare1, err := backup.DecryptSplit(walletBackup.ProviderEncryptedParts.Splits[0], providerKey1)
	assert.NoError(t, err)
	providerShare2, err := backup.DecryptSplit(walletBackup.ProviderEncryptedParts.Splits[1], providerKey2)
	assert.NoError(t, err)

	adminKeyShares := []*backup.KeySplit{adminShare1, adminShare2}
	providerKeyShares := []*backup.KeySplit{providerShare1, providerShare2}

	// Recover the wallet
	recoveredWallet, err := RecoverWallet(
		append(adminKeyShares, providerKeyShares...),
		&walletBackup.WalletBackupMetaData,
	)
	assert.NoError(t, err)
	givenWallet.Restored = true
	assert.Equal(t, givenWallet, recoveredWallet)
}

func TestSplitAndEncrypt(t *testing.T) {
	err := node.InitNode(types.State{})
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
	encryptedShares, err := SplitAndEncrypt(privateKey, encryptionPubKeys, 2, utils.ConstantSlice(1, 2), types.WalletBackupId{}, privateKey, false)
	assert.NoError(t, err)
	assert.NotNil(t, encryptedShares)
}
