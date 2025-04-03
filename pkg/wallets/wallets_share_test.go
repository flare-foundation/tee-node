package wallets

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

var (
	walletId = common.HexToHash("0x1234")
	keyId    = big.NewInt(1234)
	backupId = big.NewInt(5678)
)

func TestSplitWallet(t *testing.T) {
	// Create a test wallet with a known private key
	privateKey, err := crypto.GenerateKey()
	assert.NoError(t, err)

	wallet := &Wallet{
		WalletId:   walletId,
		KeyId:      keyId,
		PrivateKey: privateKey,
		Address:    crypto.PubkeyToAddress(privateKey.PublicKey),
	}

	// Split the wallet into shares
	numShares := 5
	threshold := 3

	splits, err := SplitWallet(wallet, backupId, numShares, threshold)
	assert.NoError(t, err)
	assert.Len(t, splits, numShares)

	// Verify that each split has the correct address
	for _, split := range splits {
		assert.Equal(t, wallet.Address.Hex(), split.Address.Hex())
	}

	// Check that shares are correctly assigned
	for _, split := range splits {
		assert.Equal(t, split.Threshold, threshold)
		assert.Equal(t, split.NumShares, numShares)
		assert.Equal(t, split.BackupId, backupId)
		assert.Equal(t, split.WalletId, walletId)
		assert.Equal(t, split.KeyId, keyId)
	}
}

func TestJointWallet(t *testing.T) {
	// Create a test wallet with a known private key
	privateKey, err := crypto.GenerateKey()
	assert.NoError(t, err)

	wallet := &Wallet{
		WalletId:   walletId,
		KeyId:      keyId,
		PrivateKey: privateKey,
		Address:    crypto.PubkeyToAddress(privateKey.PublicKey),
	}

	// Split the wallet into shares
	numShares := 5
	threshold := 3
	splits, err := SplitWallet(wallet, backupId, numShares, threshold)
	assert.NoError(t, err)

	backupIdsTriple := BackupWalletKeyIdTriple{WalletId: walletId, KeyId: keyId, BackupId: backupId}

	// Test case 1: Join the wallet using the threshold number of shares
	reconstructedWallet, err := JointWallet(splits, backupIdsTriple, wallet.Address, threshold)
	assert.NoError(t, err)
	assert.Equal(t, wallet.Address.Hex(), reconstructedWallet.Address.Hex())

	// Test case 2: Not enough shares (should fail)
	_, err = JointWallet(splits[:threshold-1], backupIdsTriple, wallet.Address, threshold)
	assert.Error(t, err)

	// Test case 3: Wrong address (should fail)
	wrongAddress := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	_, err = JointWallet(splits, backupIdsTriple, wrongAddress, threshold)
	assert.Error(t, err)

	// Test case 4: Minority shares invalid
	splits[0].Share.X = big.NewInt(99999) // Modify a share to be invalid
	reconstructedWallet, err = JointWallet(splits, backupIdsTriple, wallet.Address, threshold)
	assert.NoError(t, err)
	assert.Equal(t, wallet.Address.Hex(), reconstructedWallet.Address.Hex())

	splits[2].Share.Y = big.NewInt(232412341234) // Modify a share to be invalid
	reconstructedWallet, err = JointWallet(splits, backupIdsTriple, wallet.Address, threshold)
	assert.NoError(t, err)
	assert.Equal(t, wallet.Address.Hex(), reconstructedWallet.Address.Hex())

	// Test case 5: Invalid share set (should fail)
	splits[4].Share.Y = big.NewInt(11111) // Modify a share to be invalid
	_, err = JointWallet(splits, backupIdsTriple, wallet.Address, threshold)
	assert.Error(t, err)
}
