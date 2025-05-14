package walletactions

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	api "tee-node/api/types"
	"tee-node/pkg/node"
	"tee-node/pkg/policy"
	"tee-node/pkg/utils"
	"tee-node/pkg/wallets"
	"testing"

	testutils "tee-node/tests"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPause(t *testing.T) {
	pausers, pauserPrivKeys, _ := testutils.GenerateRandomVoters(1)

	// Test success and failure scenarios for the Pause function
	t.Run("pause functionality tests", func(t *testing.T) {
		defer wallets.DestroyState()

		walletId, keyId := setupMockWallet(t, pauserPrivKeys)
		walletIdPair := wallets.WalletKeyIdPair{WalletId: walletId, KeyId: keyId}

		isPaused, err := IsWalletPaused(walletId, keyId)
		require.NoError(t, err)
		require.False(t, isPaused)

		wallet, err := wallets.GetWallet(walletIdPair)
		require.NoError(t, err)
		wallet.WalletPauserAddresses = pausers

		pausingNonce, err := GetWalletPausingNonce(walletId, keyId)
		require.NoError(t, err)
		// Create a valid message
		validMessage := api.PauseWalletMessage{
			WalletId:     walletId,
			KeyId:        keyId,
			PausingNonce: pausingNonce,
		}

		// Create a valid signature
		messageHash, err := validMessage.Hash()
		require.NoError(t, err)

		signature, err := utils.Sign(messageHash[:], pauserPrivKeys[0])
		require.NoError(t, err)

		// Test successful pause
		err = Pause(validMessage, [][]byte{signature})
		require.NoError(t, err)
		isPaused, err = IsWalletPaused(walletId, keyId)
		require.NoError(t, err)
		assert.True(t, isPaused)

		// Test pause when already paused (should succeed with new nonce)
		err = Pause(validMessage, [][]byte{signature})
		require.Error(t, err)
		assert.Equal(t, "wallet is already paused", err.Error())
	})

	t.Run("pause with invalid messages", func(t *testing.T) {
		defer wallets.DestroyState()

		walletId, keyId := setupMockWallet(t, pauserPrivKeys)
		walletIdPair := wallets.WalletKeyIdPair{WalletId: walletId, KeyId: keyId}

		wallet, err := wallets.GetWallet(walletIdPair)
		require.NoError(t, err)
		wallet.WalletPauserAddresses = pausers

		pausingNonce, err := GetWalletPausingNonce(walletId, keyId)
		require.NoError(t, err)
		// Test non-pauser address
		invalidMessage := api.PauseWalletMessage{
			WalletId:     walletId,
			KeyId:        keyId,
			PausingNonce: pausingNonce,
		}

		messageHash, err := invalidMessage.Hash()
		require.NoError(t, err)

		privateKey, err := crypto.GenerateKey()
		require.NoError(t, err)

		signature, err := crypto.Sign(messageHash[:], privateKey)
		require.NoError(t, err)

		err = Pause(invalidMessage, [][]byte{signature})
		assert.Error(t, err)
		assert.Equal(t, "pauser address not in the list of pauserAddresses", err.Error())

		// Test invalid signature
		invalidSignature := []byte("invalid signature")
		err = Pause(invalidMessage, [][]byte{invalidSignature})
		assert.Error(t, err)
		fmt.Printf("err: %+v\n", err)

		pausingNonce, err = GetWalletPausingNonce(walletId, keyId)
		require.NoError(t, err)
		// Test with non-existent wallet
		nonExistentWalletMessage := api.PauseWalletMessage{
			WalletId:     common.HexToHash("0x11111111111"),
			KeyId:        keyId,
			PausingNonce: pausingNonce,
		}

		messageHash, err = nonExistentWalletMessage.Hash()
		require.NoError(t, err)

		signature, err = utils.Sign(messageHash[:], pauserPrivKeys[0])
		require.NoError(t, err)

		err = Pause(nonExistentWalletMessage, [][]byte{signature})
		assert.Error(t, err)
		assert.Equal(t, "wallet non-existent", err.Error())
	})
}

func TestResume(t *testing.T) {
	_, adminPrivKeys, _ := testutils.GenerateRandomVoters(2)
	// Test successful resume with valid admin signatures
	t.Run("successful resume with valid admin signatures", func(t *testing.T) {
		defer wallets.DestroyState()

		walletId, keyId := setupMockWallet(t, adminPrivKeys)
		walletIdPair := wallets.WalletKeyIdPair{WalletId: walletId, KeyId: keyId}

		randNonce, _ := utils.GenerateRandomBytes(32)
		wallet, err := wallets.GetWallet(walletIdPair)
		require.NoError(t, err)
		wallet.WalletPausingNonce = common.BytesToHash(randNonce)
		wallet.IsWalletPaused = true

		isPaused, err := IsWalletPaused(walletId, keyId)
		require.NoError(t, err)
		require.True(t, isPaused)

		pausingNonce, err := GetWalletPausingNonce(walletId, keyId)
		require.NoError(t, err)
		// Create a valid resume message
		validMessage := api.ResumeWalletMessage{
			WalletId:     walletId,
			KeyId:        keyId,
			PausingNonce: pausingNonce,
		}

		// Create valid signatures from 2 admins (meeting threshold)
		messageHash, err := validMessage.Hash()
		require.NoError(t, err)

		signature1, err := utils.Sign(messageHash[:], adminPrivKeys[0])
		require.NoError(t, err)
		signature2, err := utils.Sign(messageHash[:], adminPrivKeys[1])
		require.NoError(t, err)

		signatures := [][]byte{signature1, signature2}

		// Execute resume
		err = Resume(validMessage, signatures)
		require.NoError(t, err)
		isPaused, err = IsWalletPaused(walletId, keyId)
		require.NoError(t, err)
		assert.False(t, isPaused)
	})

	// Test resume with insufficient admin signatures
	t.Run("resume with insufficient admin signatures", func(t *testing.T) {
		defer wallets.DestroyState()

		walletId, keyId := setupMockWallet(t, adminPrivKeys)
		walletIdPair := wallets.WalletKeyIdPair{WalletId: walletId, KeyId: keyId}

		randNonce, _ := utils.GenerateRandomBytes(32)
		wallet, err := wallets.GetWallet(walletIdPair)
		require.NoError(t, err)
		wallet.WalletPausingNonce = common.BytesToHash(randNonce)
		wallet.IsWalletPaused = true // IsWalletPaused map[wallets.WalletKeyIdPair]bool

		isPaused, err := IsWalletPaused(walletId, keyId)
		require.NoError(t, err)
		require.True(t, isPaused)

		pausingNonce, err := GetWalletPausingNonce(walletId, keyId)
		require.NoError(t, err)
		// Create a valid resume message
		validMessage := api.ResumeWalletMessage{
			WalletId:     walletId,
			KeyId:        keyId,
			PausingNonce: pausingNonce,
		}

		// Create only 1 signature (below threshold of 2)
		messageHash, err := validMessage.Hash()
		require.NoError(t, err)

		signature1, err := utils.Sign(messageHash[:], adminPrivKeys[0])
		require.NoError(t, err)

		signatures := [][]byte{signature1}

		// Execute resume
		err = Resume(validMessage, signatures)
		assert.Error(t, err)
		assert.Equal(t, "threshold not met", err.Error())
		isPaused, err = IsWalletPaused(walletId, keyId)
		require.NoError(t, err)
		assert.True(t, isPaused) // Wallet should still be paused
	})

	// Test resume when not paused
	t.Run("resume when not paused", func(t *testing.T) {
		defer wallets.DestroyState()

		walletId, keyId := setupMockWallet(t, adminPrivKeys)

		isPaused, err := IsWalletPaused(walletId, keyId)
		require.NoError(t, err)
		require.False(t, isPaused)

		pausingNonce, err := GetWalletPausingNonce(walletId, keyId)
		require.NoError(t, err)

		// Create a valid resume message without pausing first
		validMessage := api.ResumeWalletMessage{
			WalletId:     walletId,
			KeyId:        keyId,
			PausingNonce: pausingNonce,
		}

		messageHash, err := validMessage.Hash()
		require.NoError(t, err)

		signature1, err := utils.Sign(messageHash[:], adminPrivKeys[0])
		require.NoError(t, err)
		signature2, err := utils.Sign(messageHash[:], adminPrivKeys[1])
		require.NoError(t, err)

		signatures := [][]byte{signature1, signature2}

		// Execute resume
		err = Resume(validMessage, signatures)
		assert.Error(t, err)
		assert.Equal(t, "wallet is not paused", err.Error())
	})
}

func TestSetPausingAddresses(t *testing.T) {
	pausers, _, _ := testutils.GenerateRandomVoters(1)

	_, adminPrivKeys, _ := testutils.GenerateRandomVoters(2)

	// Test successful update of pausing addresses
	t.Run("successful set pausing addresses", func(t *testing.T) {
		defer wallets.DestroyState()

		walletId, keyId := setupMockWallet(t, adminPrivKeys)

		isPaused, err := IsWalletPaused(walletId, keyId)
		require.NoError(t, err)
		require.False(t, isPaused)

		// Get current nonce for comparison
		currentNonce, err := GetWalletPausingAddressSetupNonce(walletId, keyId)
		require.NoError(t, err)

		// Create a valid message with a higher nonce
		newNonce := new(big.Int).Add(&currentNonce, big.NewInt(1))
		validMessage := api.PausingAddressSetWalletMessage{
			PauserAddressSetupNonce: *newNonce,
			WalletId:                walletId,
			KeyId:                   keyId,
			PausingAddresses:        pausers,
		}

		// Sign the message with enough admins to meet threshold
		messageHash, err := validMessage.Hash()
		require.NoError(t, err)

		signature1, err := utils.Sign(messageHash[:], adminPrivKeys[0])
		require.NoError(t, err)
		signature2, err := utils.Sign(messageHash[:], adminPrivKeys[1])
		require.NoError(t, err)

		signatures := [][]byte{signature1, signature2}

		// Execute set pausing addresses
		err = SetPausingAddresses(validMessage, signatures)
		require.NoError(t, err)

		// Verify the pausing addresses were updated
		pausingAddresses, err := GetWalletPausingAddresses(walletId, keyId)
		require.NoError(t, err)
		assert.Equal(t, pausers, pausingAddresses)
		setupNonce, err := GetWalletPausingAddressSetupNonce(walletId, keyId)
		require.NoError(t, err)
		assert.Equal(t, *newNonce, setupNonce)
	})

	// Test failure with invalid nonce
	t.Run("failed set pausing addresses with invalid nonce", func(t *testing.T) {
		defer wallets.DestroyState()

		walletId, keyId := setupMockWallet(t, adminPrivKeys)

		isPaused, err := IsWalletPaused(walletId, keyId)
		require.NoError(t, err)
		require.False(t, isPaused)

		// Get current nonce
		currentNonce, err := GetWalletPausingAddressSetupNonce(walletId, keyId)
		require.NoError(t, err)

		// Create a message with the same nonce (should fail)
		invalidMessage := api.PausingAddressSetWalletMessage{
			PauserAddressSetupNonce: currentNonce, // Same nonce, should be rejected
			WalletId:                walletId,
			KeyId:                   keyId,
			PausingAddresses:        pausers,
		}

		// Sign the message
		messageHash, err := invalidMessage.Hash()
		require.NoError(t, err)

		signature1, err := utils.Sign(messageHash[:], adminPrivKeys[0])
		require.NoError(t, err)
		signature2, err := utils.Sign(messageHash[:], adminPrivKeys[1])
		require.NoError(t, err)

		signatures := [][]byte{signature1, signature2}

		// Execute set pausing addresses
		err = SetPausingAddresses(invalidMessage, signatures)
		assert.Error(t, err)
		assert.Equal(t, "pauser address setup nonce mismatch", err.Error())

		// Verify the pausing addresses weren't updated
		pausingAddresses, err := GetWalletPausingAddresses(walletId, keyId)
		require.NoError(t, err)
		assert.Nil(t, pausingAddresses)
	})
}

func setupMockWallet(t *testing.T, adminPrivKeys []*ecdsa.PrivateKey) (common.Hash, uint64) {
	_ = node.InitNode()
	nodeId := node.GetNodeInfo()

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	walletId := common.HexToHash("0xabcdef")
	keyId := uint64(1)

	testutils.CreateMockWallet(t, nodeId.TeeId, walletId, keyId, policy.GetActiveSigningPolicy().RewardEpochId, privKeys, adminPrivKeys, nil)

	return walletId, keyId
}
