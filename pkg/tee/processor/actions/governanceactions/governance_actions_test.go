package governanceactions

// import (
// 	"crypto/ecdsa"
// 	"math/big"
// 	"tee-node/api/types"
// 	"tee-node/pkg/tee/node"
// 	"tee-node/pkg/tee/utils"
// 	"testing"

// 	testutils "tee-node/testutils"

// 	"github.com/ethereum/go-ethereum/common"
// 	"github.com/ethereum/go-ethereum/crypto"
// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/require"
// )

// func TestPause(t *testing.T) {

// 	pausers, pauserPrivKeys, _ := testutils.GenerateRandomVoters(1)

// 	_ = node.InitNode()
// 	nodeId := node.GetNodeInfo()

// 	// Test success and failure scenarios for the Pause function
// 	t.Run("pause functionality tests", func(t *testing.T) {
// 		defer node.DestroyState()

// 		pausingNonce := GetTeePausingNonce()
// 		node.PausingAddressesStorage.TeePauserAddresses = pausers

// 		// Create a valid message
// 		validMessage := types.PauseTeeMessage{
// 			TeeId:        nodeId.TeeId,
// 			PausingNonce: pausingNonce,
// 		}

// 		// Create a valid signature
// 		messageHash, err := validMessage.Hash()
// 		require.NoError(t, err)

// 		signature, err := utils.Sign(messageHash[:], pauserPrivKeys[0])
// 		require.NoError(t, err)

// 		// Test successful pause
// 		err = Pause(validMessage, [][]byte{signature})
// 		require.NoError(t, err)
// 		assert.NotNil(t, pausingNonce)
// 		originalNonce := pausingNonce
// 		require.NotNil(t, originalNonce)

// 		// Test pause when already paused (should succeed but not change nonce)
// 		err = Pause(validMessage, [][]byte{signature})
// 		require.Error(t, err)
// 		if err.Error() != "node is already paused" {
// 			t.Errorf("expected 'node is already paused', got %v", err)
// 		}

// 	})

// 	t.Run("pause with invalid messages", func(t *testing.T) {
// 		defer node.DestroyState()

// 		pausingNonce := GetTeePausingNonce()
// 		node.PausingAddressesStorage.TeePauserAddresses = pausers

// 		// Test non-pauser address
// 		invalidMessage := types.PauseTeeMessage{
// 			TeeId:        nodeId.TeeId,
// 			PausingNonce: pausingNonce,
// 		}

// 		messageHash, err := invalidMessage.Hash()
// 		require.NoError(t, err)

// 		privateKey, err := crypto.GenerateKey()
// 		require.NoError(t, err)

// 		signature, err := crypto.Sign(messageHash[:], privateKey)
// 		require.NoError(t, err)

// 		err = Pause(invalidMessage, [][]byte{signature})
// 		assert.Error(t, err)
// 		assert.Equal(t, "pauser address not in the list of pauserAddresses", err.Error())

// 		// Test invalid signature
// 		invalidSignature := []byte("invalid signature")
// 		err = Pause(invalidMessage, [][]byte{invalidSignature})
// 		assert.Error(t, err)

// 		// Test With invalid PausingNonce
// 		invalidMessage.PausingNonce = common.HexToHash("0x1234567890")

// 		err = Pause(invalidMessage, [][]byte{signature})
// 		assert.Error(t, err)
// 		assert.Equal(t, "pausing nonce mismatch", err.Error())
// 	})
// }

// func TestResume(t *testing.T) {
// 	signers, signerPrivKeys, _ := testutils.GenerateRandomVoters(3)
// 	pausers, pauserPrivKeys, _ := testutils.GenerateRandomVoters(1)

// 	_ = node.InitNode()
// 	nodeId := node.GetNodeInfo()

// 	// Test successful resume with valid governance signatures
// 	t.Run("successful resume with valid governance signatures", func(t *testing.T) {
// 		defer node.DestroyState()

// 		pausingNonce := GetTeePausingNonce()
// 		governancePolicy := node.GetGovernancePolicy()
// 		governancePolicy.Signers = signers
// 		governancePolicy.Threshold = 2 // Require 2 out of 3 signatures
// 		node.PausingAddressesStorage.TeePauserAddresses = pausers
// 		governanceHash, _ := governancePolicy.Hash()
// 		PauseNode(t, nodeId, pausingNonce, pauserPrivKeys)

// 		// Create a valid message
// 		validMessage := types.ResumeTeeMessage{
// 			GovernanceHash: governanceHash,
// 			ResumePairs: []types.ResumeTeeIdNoncePair{
// 				{
// 					TeeId:        nodeId.TeeId,
// 					PausingNonce: pausingNonce,
// 				},
// 			},
// 		}

// 		// Create valid signatures from 2 signers (meeting threshold)
// 		messageHash, err := validMessage.Hash()
// 		require.NoError(t, err)

// 		signature1, err := utils.Sign(messageHash[:], signerPrivKeys[0])
// 		require.NoError(t, err)
// 		signature2, err := utils.Sign(messageHash[:], signerPrivKeys[1])
// 		require.NoError(t, err)

// 		signatures := [][]byte{signature1, signature2}

// 		// Execute resume
// 		err = Resume(validMessage, signatures)
// 		require.NoError(t, err)
// 		isPaused := IsTeePaused()
// 		assert.False(t, isPaused)
// 	})

// 	// Test resume with insufficient governance signatures
// 	t.Run("resume with insufficient governance signatures", func(t *testing.T) {
// 		defer node.DestroyState()

// 		pausingNonce := GetTeePausingNonce()
// 		governancePolicy := node.GetGovernancePolicy()
// 		governancePolicy.Signers = signers
// 		governancePolicy.Threshold = 2 // Require 2 out of 3 signatures
// 		node.PausingAddressesStorage.TeePauserAddresses = pausers
// 		governanceHash, _ := governancePolicy.Hash()
// 		PauseNode(t, nodeId, pausingNonce, pauserPrivKeys)

// 		validMessage := types.ResumeTeeMessage{
// 			GovernanceHash: governanceHash,
// 			ResumePairs: []types.ResumeTeeIdNoncePair{
// 				{
// 					TeeId:        nodeId.TeeId,
// 					PausingNonce: pausingNonce,
// 				},
// 			},
// 		}

// 		// Create only 1 signature (below threshold of 2)
// 		messageHash, err := validMessage.Hash()
// 		require.NoError(t, err)

// 		signature1, err := utils.Sign(messageHash[:], signerPrivKeys[0])
// 		require.NoError(t, err)

// 		signatures := [][]byte{signature1}

// 		// Execute resume
// 		err = Resume(validMessage, signatures)
// 		assert.Error(t, err)
// 		assert.Equal(t, "threshold not met", err.Error())
// 		isPaused := IsTeePaused()
// 		assert.True(t, isPaused) // Node should still be paused
// 	})

// 	// Test resume when not paused
// 	t.Run("resume when not paused", func(t *testing.T) {
// 		defer node.DestroyState()

// 		pausingNonce := GetTeePausingNonce()
// 		governancePolicy := node.GetGovernancePolicy()
// 		governancePolicy.Signers = signers
// 		governancePolicy.Threshold = 2 // Require 2 out of 3 signatures
// 		node.PausingAddressesStorage.TeePauserAddresses = pausers
// 		governanceHash, _ := governancePolicy.Hash()
// 		node.PausingNoncesStorage.IsTeePaused = false

// 		validMessage := types.ResumeTeeMessage{
// 			GovernanceHash: governanceHash,
// 			ResumePairs: []types.ResumeTeeIdNoncePair{
// 				{
// 					TeeId:        nodeId.TeeId,
// 					PausingNonce: pausingNonce,
// 				},
// 			},
// 		}

// 		messageHash, err := validMessage.Hash()
// 		require.NoError(t, err)

// 		signature1, err := utils.Sign(messageHash[:], signerPrivKeys[0])
// 		require.NoError(t, err)
// 		signature2, err := utils.Sign(messageHash[:], signerPrivKeys[1])
// 		require.NoError(t, err)

// 		signatures := [][]byte{signature1, signature2}

// 		// Execute resume
// 		err = Resume(validMessage, signatures)
// 		assert.Error(t, err)
// 		assert.Equal(t, "node is not paused", err.Error())
// 	})

// 	// Test resume with invalid pausing nonce
// 	t.Run("resume with invalid pausing nonce", func(t *testing.T) {
// 		defer node.DestroyState()

// 		pausingNonce := GetTeePausingNonce()
// 		governancePolicy := node.GetGovernancePolicy()
// 		governancePolicy.Signers = signers
// 		governancePolicy.Threshold = 2 // Require 2 out of 3 signatures
// 		node.PausingAddressesStorage.TeePauserAddresses = pausers
// 		governanceHash, _ := governancePolicy.Hash()
// 		PauseNode(t, nodeId, pausingNonce, pauserPrivKeys)

// 		// Create message with incorrect nonce
// 		invalidNonceMessage := types.ResumeTeeMessage{
// 			GovernanceHash: governanceHash,
// 			ResumePairs: []types.ResumeTeeIdNoncePair{
// 				{
// 					TeeId:        nodeId.TeeId,
// 					PausingNonce: common.HexToHash("0x1234567890123456789012345678901234567890123456789012345678901234"), // Invalid nonce
// 				},
// 			},
// 		}

// 		messageHash, err := invalidNonceMessage.Hash()
// 		require.NoError(t, err)

// 		signature1, err := utils.Sign(messageHash[:], signerPrivKeys[0])
// 		require.NoError(t, err)
// 		signature2, err := utils.Sign(messageHash[:], signerPrivKeys[1])
// 		require.NoError(t, err)

// 		signatures := [][]byte{signature1, signature2}

// 		// Execute resume
// 		err = Resume(invalidNonceMessage, signatures)
// 		assert.Error(t, err)
// 		assert.Equal(t, "no matching pausing nonce found", err.Error())
// 	})

// 	// Test resume with multiple valid pairs (only one should match)
// 	t.Run("resume with multiple valid pairs", func(t *testing.T) {
// 		defer node.DestroyState()

// 		pausingNonce := GetTeePausingNonce()
// 		governancePolicy := node.GetGovernancePolicy()
// 		governancePolicy.Signers = signers
// 		governancePolicy.Threshold = 2 // Require 2 out of 3 signatures
// 		node.PausingAddressesStorage.TeePauserAddresses = pausers
// 		governanceHash, _ := governancePolicy.Hash()
// 		PauseNode(t, nodeId, pausingNonce, pauserPrivKeys)

// 		// Create message with multiple resume pairs, including the correct one
// 		multiPairMessage := types.ResumeTeeMessage{
// 			GovernanceHash: governanceHash,
// 			ResumePairs: []types.ResumeTeeIdNoncePair{
// 				{
// 					TeeId:        common.HexToAddress("0x1234567890123456789012345678901234567890"),                      // Invalid TEE ID
// 					PausingNonce: common.HexToHash("0x1234567890123456789012345678901234567890123456789012345678901234"), // Invalid nonce
// 				},
// 				{
// 					TeeId:        nodeId.TeeId,
// 					PausingNonce: pausingNonce, // Correct nonce
// 				},
// 				{
// 					TeeId:        common.HexToAddress("0x3456789012345678901234567890123456789012"),                      // Another invalid TEE ID
// 					PausingNonce: common.HexToHash("0x3456789012345678901234567890123456789012345678901234567890123456"), // Another invalid nonce
// 				},
// 			},
// 		}

// 		messageHash, err := multiPairMessage.Hash()
// 		require.NoError(t, err)

// 		signature1, err := utils.Sign(messageHash[:], signerPrivKeys[0])
// 		require.NoError(t, err)
// 		signature2, err := utils.Sign(messageHash[:], signerPrivKeys[1])
// 		require.NoError(t, err)

// 		signatures := [][]byte{signature1, signature2}

// 		// Execute resume
// 		err = Resume(multiPairMessage, signatures)
// 		require.NoError(t, err)
// 		isPaused := IsTeePaused()
// 		assert.False(t, isPaused) // Node should be resumed
// 	})

// }

// func TestSetPausingAddresses(t *testing.T) {
// 	signers, signerPrivKeys, _ := testutils.GenerateRandomVoters(3)
// 	newPausers, _, _ := testutils.GenerateRandomVoters(2)

// 	_ = node.InitNode()
// 	nodeId := node.GetNodeInfo()

// 	// Test successful update of pausing addresses
// 	t.Run("successful set pausing addresses", func(t *testing.T) {
// 		defer node.DestroyState()

// 		// Setup governance policy
// 		governancePolicy := node.GetGovernancePolicy()
// 		governancePolicy.Signers = signers
// 		governancePolicy.Threshold = 2 // Require 2 out of 3 signatures

// 		// Get current nonce for comparison
// 		currentNonce := GetTeePausingAddressSetupNonce()

// 		// Create a valid message with a higher nonce
// 		newNonce := new(big.Int).Add(&currentNonce, big.NewInt(1))
// 		validMessage := types.PausingAddressSetMessage{
// 			GovernanceHash: governanceHash(t),
// 			PausingAddressSettings: []types.PausingAddressSettings{
// 				{
// 					PauserAddressSetupNonce: *newNonce,
// 					TeeId:                   nodeId.TeeId,
// 					PausingAddresses:        newPausers,
// 				},
// 			},
// 		}

// 		// Sign the message with enough signers to meet threshold
// 		messageHash, err := validMessage.Hash()
// 		require.NoError(t, err)

// 		signature1, err := utils.Sign(messageHash[:], signerPrivKeys[0])
// 		require.NoError(t, err)
// 		signature2, err := utils.Sign(messageHash[:], signerPrivKeys[1])
// 		require.NoError(t, err)

// 		signatures := [][]byte{signature1, signature2}

// 		// Execute set pausing addresses
// 		err = SetPausingAddresses(validMessage, signatures)
// 		require.NoError(t, err)

// 		// Verify the pausing addresses were updated
// 		assert.Equal(t, newPausers, node.PausingAddressesStorage.TeePauserAddresses)
// 		assert.Equal(t, *newNonce, node.PausingAddressesStorage.TeePauserAddressSetupNonce)
// 	})

// 	// Test failure with invalid nonce
// 	t.Run("failed set pausing addresses with invalid nonce", func(t *testing.T) {
// 		defer node.DestroyState()

// 		// Setup governance policy
// 		governancePolicy := node.GetGovernancePolicy()
// 		governancePolicy.Signers = signers
// 		governancePolicy.Threshold = 2 // Require 2 out of 3 signatures

// 		// Pause the node first (required for governance operations)
// 		pausers, _, _ := testutils.GenerateRandomVoters(1)
// 		node.PausingAddressesStorage.TeePauserAddresses = pausers

// 		// Get current nonce
// 		currentNonce := GetTeePausingAddressSetupNonce()

// 		// Create a message with the same nonce (should fail)
// 		invalidMessage := types.PausingAddressSetMessage{
// 			GovernanceHash: governanceHash(t),
// 			PausingAddressSettings: []types.PausingAddressSettings{
// 				{
// 					PauserAddressSetupNonce: currentNonce, // Same nonce, should be rejected
// 					TeeId:                   nodeId.TeeId,
// 					PausingAddresses:        newPausers,
// 				},
// 			},
// 		}

// 		// Sign the message
// 		messageHash, err := invalidMessage.Hash()
// 		require.NoError(t, err)

// 		signature1, err := utils.Sign(messageHash[:], signerPrivKeys[0])
// 		require.NoError(t, err)
// 		signature2, err := utils.Sign(messageHash[:], signerPrivKeys[1])
// 		require.NoError(t, err)

// 		signatures := [][]byte{signature1, signature2}

// 		// Execute set pausing addresses
// 		err = SetPausingAddresses(invalidMessage, signatures)
// 		assert.Error(t, err)
// 		assert.Equal(t, "new pauser address setup nonce is too small", err.Error())

// 		// Verify the pausing addresses weren't updated
// 		assert.Equal(t, pausers, node.PausingAddressesStorage.TeePauserAddresses)
// 	})
// }

// func TestNewUpgradePath(t *testing.T) {
// 	signers, signerPrivKeys, _ := testutils.GenerateRandomVoters(3)

// 	_ = node.InitNode()

// 	// Test successful addition of upgrade path
// 	t.Run("successful add upgrade path", func(t *testing.T) {
// 		defer node.DestroyState()

// 		// Setup governance policy
// 		governancePolicy := node.GetGovernancePolicy()
// 		governancePolicy.Signers = signers
// 		governancePolicy.Threshold = 2 // Require 2 out of 3 signatures

// 		// Pause the node first (required for governance operations)
// 		pausers, _, _ := testutils.GenerateRandomVoters(1)
// 		node.PausingAddressesStorage.TeePauserAddresses = pausers

// 		// Count current upgrade paths
// 		codeVersionStorage := node.GetCodeVersionStorage()
// 		initialValidUpgradesCount := len(codeVersionStorage.ValidUpdgradeVersions)

// 		SelfCodeVersion := codeVersionStorage.SelfVersion

// 		// Create valid upgrade path message
// 		validMessage := types.UpgradePathMessage{
// 			GovernanceHash: governanceHash(t),
// 			UpgradePaths: []types.UpgradePath{
// 				{
// 					InitialSet: []types.CodeVersion{
// 						SelfCodeVersion,
// 					},
// 					TargetSet: []types.CodeVersion{
// 						{
// 							Platform: "platform2",
// 							CodeHash: common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
// 						},
// 					},
// 				},
// 			},
// 		}

// 		// Sign the message
// 		messageHash, err := validMessage.Hash()
// 		require.NoError(t, err)

// 		signature1, err := utils.Sign(messageHash[:], signerPrivKeys[0])
// 		require.NoError(t, err)
// 		signature2, err := utils.Sign(messageHash[:], signerPrivKeys[1])
// 		require.NoError(t, err)

// 		signatures := [][]byte{signature1, signature2}

// 		// Execute add upgrade path
// 		err = NewUpgradePath(validMessage, signatures)
// 		require.NoError(t, err)

// 		// Verify upgrade path was added
// 		assert.Equal(t, initialValidUpgradesCount+1, len(codeVersionStorage.ValidUpdgradeVersions))
// 	})
// }

// func TestBanVersion(t *testing.T) {
// 	signers, signerPrivKeys, _ := testutils.GenerateRandomVoters(3)

// 	_ = node.InitNode()

// 	// Test successful ban version
// 	t.Run("successful ban version", func(t *testing.T) {
// 		defer node.DestroyState()

// 		// Setup governance policy
// 		governancePolicy := node.GetGovernancePolicy()
// 		governancePolicy.Signers = signers
// 		governancePolicy.Threshold = 2 // Require 2 out of 3 signatures

// 		// Pause the node first (required for governance operations)
// 		pausers, _, _ := testutils.GenerateRandomVoters(1)
// 		node.PausingAddressesStorage.TeePauserAddresses = pausers

// 		// Create a hash to ban
// 		hashToBan := common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333")

// 		// Create valid ban version message
// 		validMessage := types.BanVersionMessage{
// 			GovernanceHash: governanceHash(t),
// 			CodeVersions: []types.CodeVersion{
// 				{
// 					Platform: "platform1",
// 					CodeHash: hashToBan,
// 				},
// 			},
// 		}

// 		// Sign the message
// 		messageHash, err := validMessage.Hash()
// 		require.NoError(t, err)

// 		signature1, err := utils.Sign(messageHash[:], signerPrivKeys[0])
// 		require.NoError(t, err)
// 		signature2, err := utils.Sign(messageHash[:], signerPrivKeys[1])
// 		require.NoError(t, err)

// 		signatures := [][]byte{signature1, signature2}

// 		// Execute ban version
// 		err = BanVersion(validMessage, signatures)
// 		require.NoError(t, err)

// 		// Verify the version was banned
// 		codeVersionStorage := node.GetCodeVersionStorage()
// 		assert.True(t, codeVersionStorage.BannedVersions[hashToBan])
// 	})

// 	// Test failure with insufficient signatures
// 	t.Run("failed ban version with insufficient signatures", func(t *testing.T) {
// 		defer node.DestroyState()

// 		// Setup governance policy
// 		governancePolicy := node.GetGovernancePolicy()
// 		governancePolicy.Signers = signers
// 		governancePolicy.Threshold = 2 // Require 2 out of 3 signatures

// 		// Pause the node first (required for governance operations)
// 		pausers, _, _ := testutils.GenerateRandomVoters(1)
// 		node.PausingAddressesStorage.TeePauserAddresses = pausers

// 		// Create a hash to ban
// 		hashToBan := common.HexToHash("0x4444444444444444444444444444444444444444444444444444444444444444")

// 		// Create valid ban version message
// 		validMessage := types.BanVersionMessage{
// 			GovernanceHash: governanceHash(t),
// 			CodeVersions: []types.CodeVersion{
// 				{
// 					Platform: "platform1",
// 					CodeHash: hashToBan,
// 				},
// 			},
// 		}

// 		// Sign the message but with insufficient signatures
// 		messageHash, err := validMessage.Hash()
// 		require.NoError(t, err)

// 		signature1, err := utils.Sign(messageHash[:], signerPrivKeys[0])
// 		require.NoError(t, err)

// 		signatures := [][]byte{signature1} // Only one signature, below threshold

// 		// Execute ban version
// 		err = BanVersion(validMessage, signatures)
// 		assert.Error(t, err)
// 		assert.Equal(t, "threshold not met", err.Error())

// 		// Verify the version was not banned
// 		codeVersionStorage := node.GetCodeVersionStorage()
// 		assert.False(t, codeVersionStorage.BannedVersions[hashToBan])
// 	})
// }

// // Helper function to get governance hash
// func governanceHash(t *testing.T) common.Hash {
// 	governancePolicy := node.GetGovernancePolicy()
// 	hash, err := governancePolicy.Hash()
// 	require.NoError(t, err)
// 	return hash
// }

// func PauseNode(t *testing.T, nodeId node.NodeInfo, pausingNonce common.Hash, pauserPrivKeys []*ecdsa.PrivateKey) {
// 	pauseMessage := types.PauseTeeMessage{
// 		TeeId:        nodeId.TeeId,
// 		PausingNonce: pausingNonce,
// 	}

// 	messageHash, _ := pauseMessage.Hash()
// 	signature, _ := utils.Sign(messageHash[:], pauserPrivKeys[0])

// 	err := Pause(pauseMessage, [][]byte{signature})
// 	require.NoError(t, err)
// }
