package policyutils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	commonpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/stretchr/testify/require"

	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/policy"
	"github.com/flare-foundation/tee-node/pkg/types"
)

// Test constants
const numVoters = 100

// policyTestSetup holds common test setup data for policy tests
type policyTestSetup struct {
	pStorage      *policy.Storage
	processor     Processor
	voters        []common.Address
	privKeys      []*ecdsa.PrivateKey
	pubKeysMap    map[common.Address]*ecdsa.PublicKey
	pubKeys       []types.PublicKey
	initialPolicy *commonpolicy.SigningPolicy
	randSeed      int64
}

// setupPolicyTest creates a standard test environment for policy tests
func setupPolicyTest(t *testing.T) *policyTestSetup {
	t.Helper()

	pStorage := policy.InitializeStorage()
	processor := NewProcessor(pStorage)

	epochID := uint32(1)
	n, err := rand.Int(rand.Reader, big.NewInt(100000000))
	require.NoError(t, err)
	randSeed := n.Int64()

	voters, privKeys, pubKeysMap := testutils.GenerateRandomKeys(t, numVoters)
	initialPolicy := testutils.GenerateRandomPolicyData(t, epochID, voters, randSeed)

	pubKeys := make([]types.PublicKey, len(voters))
	for i, voter := range voters {
		pubKeys[i] = types.PubKeyToStruct(pubKeysMap[voter])
	}

	return &policyTestSetup{
		pStorage:      pStorage,
		processor:     processor,
		voters:        voters,
		privKeys:      privKeys,
		pubKeysMap:    pubKeysMap,
		pubKeys:       pubKeys,
		initialPolicy: initialPolicy,
		randSeed:      randSeed,
	}
}

// setupPolicyTestWithInitializedPolicy creates a test environment with policy already initialized
func setupPolicyTestWithInitializedPolicy(t *testing.T) *policyTestSetup {
	t.Helper()

	setup := setupPolicyTest(t)

	_, err := node.Initialize(node.ZeroState{})
	require.NoError(t, err)

	err = setup.pStorage.SetInitialPolicy(setup.initialPolicy, setup.pubKeysMap)
	require.NoError(t, err)

	return setup
}

// generateNextPolicy generates a policy for the next epoch
func (s *policyTestSetup) generateNextPolicy(t *testing.T, offset uint32) (*commonpolicy.SigningPolicy, []types.PublicKey) {
	t.Helper()

	nextEpochID := s.initialPolicy.RewardEpochID + offset
	nextPolicy := testutils.GenerateRandomPolicyData(t, nextEpochID, s.voters, s.randSeed+int64(offset))

	pubKeys := make([]types.PublicKey, len(s.voters))
	for i, voter := range s.voters {
		pubKeys[i] = types.PubKeyToStruct(s.pubKeysMap[voter])
	}

	return nextPolicy, pubKeys
}

// executeInitializePolicy executes InitializePolicy with the given request
func (s *policyTestSetup) executeInitializePolicy(t *testing.T, req *types.InitializePolicyRequest) ([]byte, error) {
	t.Helper()

	message, err := json.Marshal(req)
	require.NoError(t, err)

	return s.processor.InitializePolicy(&types.DirectInstruction{Message: message})
}

// executeUpdatePolicy executes UpdatePolicy with the given request
func (s *policyTestSetup) executeUpdatePolicy(t *testing.T, req *types.UpdatePolicyRequest) ([]byte, error) {
	t.Helper()

	message, err := json.Marshal(req)
	require.NoError(t, err)

	return s.processor.UpdatePolicy(&types.DirectInstruction{Message: message})
}

func TestInitializePolicyBasicFlow(t *testing.T) {
	setup := setupPolicyTest(t)

	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: setup.initialPolicy.RawBytes(),
		PublicKeys:         setup.pubKeys,
	}
	_, err := setup.executeInitializePolicy(t, req)
	require.NoError(t, err)

	activePolicy, err := setup.pStorage.ActiveSigningPolicy()
	require.NoError(t, err)
	require.Equal(t, setup.initialPolicy.RewardEpochID, activePolicy.RewardEpochID)
	require.Equal(t, setup.initialPolicy.Hash(), activePolicy.Hash())
}

func TestInitializePolicyAlreadyInitialized(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	// Try to initialize again with a different policy
	newEpochID := uint32(2)
	newPolicy := testutils.GenerateRandomPolicyData(t, newEpochID, setup.voters, int64(54321))

	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: newPolicy.RawBytes(),
		PublicKeys:         setup.pubKeys,
	}
	_, err := setup.executeInitializePolicy(t, req)
	require.Error(t, err)
	require.Equal(t, "policy already initialized", err.Error())
}

func TestInitializePolicyInvalidJSON(t *testing.T) {
	setup := setupPolicyTest(t)

	invalidMessage := []byte(`{"invalid": "json"`)
	_, err := setup.processor.InitializePolicy(&types.DirectInstruction{Message: invalidMessage})
	require.Error(t, err)
}

func TestInitializePolicyInvalidPolicyBytes(t *testing.T) {
	setup := setupPolicyTest(t)

	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: []byte{0x01, 0x02, 0x03}, // Invalid policy bytes
		PublicKeys:         setup.pubKeys,
	}

	_, err := setup.executeInitializePolicy(t, req)
	require.Error(t, err)
}

func TestInitializePolicyEmptyPolicyBytes(t *testing.T) {
	setup := setupPolicyTest(t)

	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: []byte{},
		PublicKeys:         setup.pubKeys,
	}

	_, err := setup.executeInitializePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "message too short for decoding signing policy")
}

func TestInitializePolicyMismatchedPublicKeysCount(t *testing.T) {
	setup := setupPolicyTest(t)

	// Provide fewer public keys than voters
	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: setup.initialPolicy.RawBytes(),
		PublicKeys:         setup.pubKeys[:numVoters/2],
	}
	_, err := setup.executeInitializePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "number of public keys and the number of voters do not match")
}

func TestInitializePolicyEmptyPublicKeys(t *testing.T) {
	setup := setupPolicyTest(t)

	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: setup.initialPolicy.RawBytes(),
		PublicKeys:         []types.PublicKey{},
	}
	_, err := setup.executeInitializePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "number of public keys and the number of voters do not match")
}

func TestInitializePolicyWrongPublicKeyAddress(t *testing.T) {
	for range 10 {
		setup := setupPolicyTest(t)

		// Replace first public key with a different one
		wrongPubKeys := make([]types.PublicKey, len(setup.pubKeys))

		copy(wrongPubKeys, setup.pubKeys)

		wrongPubKeys[0] = types.PublicKey{
			X: [32]byte{0, 1, 2, 3}, // not a valid public key
			Y: [32]byte{3, 4, 5, 6},
		}

		req := &types.InitializePolicyRequest{
			InitialPolicyBytes: setup.initialPolicy.RawBytes(),
			PublicKeys:         wrongPubKeys,
		}
		_, err := setup.executeInitializePolicy(t, req)
		require.Contains(t, err.Error(), "invalid public key bytes")
		require.Error(t, err)

		// Generate a new key that doesn't match the first voter, but is a valid public key
		newPrivKey, err := crypto.GenerateKey()
		require.NoError(t, err)

		wrongPubKeys[0] = types.PublicKey{
			X: common.BigToHash(newPrivKey.X),
			Y: common.BigToHash(newPrivKey.Y),
		}

		req2 := &types.InitializePolicyRequest{
			InitialPolicyBytes: setup.initialPolicy.RawBytes(),
			PublicKeys:         wrongPubKeys,
		}
		_, err = setup.executeInitializePolicy(t, req2)
		require.Contains(t, err.Error(), "public key and address do not match")
		require.Error(t, err)
	}
}

func TestInitializePolicyRollbackOnError(t *testing.T) {
	setup := setupPolicyTest(t)

	// Try to initialize with invalid public keys
	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: setup.initialPolicy.RawBytes(),
		PublicKeys:         setup.pubKeys[:numVoters/2],
	}
	_, err := setup.executeInitializePolicy(t, req)
	require.Error(t, err)

	// Verify storage was rolled back (DestroyState was called)
	_, err = setup.pStorage.ActiveSigningPolicy()
	require.Error(t, err)
	require.Equal(t, "signing policy not initialized", err.Error())
}

func TestUpdatePolicyBasicFlow(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	// Generate next policy
	nextPolicy, pubKeys := setup.generateNextPolicy(t, 1)

	req := &types.UpdatePolicyRequest{
		NewPolicy:  testutils.BuildMultiSignedPolicy(t, nextPolicy.RawBytes(), setup.privKeys),
		PublicKeys: pubKeys,
	}
	_, err := setup.executeUpdatePolicy(t, req)
	require.NoError(t, err)

	// Verify the policy was updated
	activePolicy, err := setup.pStorage.ActiveSigningPolicy()
	require.NoError(t, err)
	require.Equal(t, nextPolicy.RewardEpochID, activePolicy.RewardEpochID)
	require.Equal(t, nextPolicy.Hash(), activePolicy.Hash())
}

func TestUpdatePolicyNotInitialized(t *testing.T) {
	setup := setupPolicyTest(t)

	// Try to update without initializing first
	nextPolicy, pubKeys := setup.generateNextPolicy(t, 1)
	req := &types.UpdatePolicyRequest{
		NewPolicy:  testutils.BuildMultiSignedPolicy(t, nextPolicy.RawBytes(), setup.privKeys),
		PublicKeys: pubKeys,
	}

	_, err := setup.executeUpdatePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "signing policy not initialized")
}

func TestUpdatePolicyInvalidJSON(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	invalidMessage := []byte(`{"invalid": "json"`)
	_, err := setup.processor.UpdatePolicy(&types.DirectInstruction{Message: invalidMessage})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected end of JSON input")
}

func TestUpdatePolicyInvalidPolicyBytes(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	req := &types.UpdatePolicyRequest{
		NewPolicy: types.MultiSignedPolicy{
			PolicyBytes: []byte{0x01, 0x02, 0x03},
			Signatures:  [][]byte{},
		},
		PublicKeys: setup.pubKeys,
	}

	_, err := setup.executeUpdatePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "message too short for decoding signing policy")
}

func TestUpdatePolicyEmptyPolicyBytes(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	req := &types.UpdatePolicyRequest{
		NewPolicy: types.MultiSignedPolicy{
			PolicyBytes: []byte{},
			Signatures:  [][]byte{},
		},
		PublicKeys: setup.pubKeys,
	}

	_, err := setup.executeUpdatePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "message too short for decoding signing policy")
}

func TestUpdatePolicyWrongEpochID(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	// Generate policy with wrong epoch (skip one)
	wrongEpochID := setup.initialPolicy.RewardEpochID + 2
	wrongPolicy := testutils.GenerateRandomPolicyData(t, wrongEpochID, setup.voters, setup.randSeed+2)

	req := &types.UpdatePolicyRequest{
		NewPolicy:  testutils.BuildMultiSignedPolicy(t, wrongPolicy.RawBytes(), setup.privKeys),
		PublicKeys: setup.pubKeys,
	}
	_, err := setup.executeUpdatePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "policy is not active")
}

func TestUpdatePolicySameEpochID(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	// Try to update with same epoch ID
	sameEpochPolicy := testutils.GenerateRandomPolicyData(t, setup.initialPolicy.RewardEpochID, setup.voters, setup.randSeed+100)

	req := &types.UpdatePolicyRequest{
		NewPolicy:  testutils.BuildMultiSignedPolicy(t, sameEpochPolicy.RawBytes(), setup.privKeys),
		PublicKeys: setup.pubKeys,
	}
	_, err := setup.executeUpdatePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "policy is not active")
}

func TestUpdatePolicyInsufficientSignatures(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	nextPolicy, pubKeys := setup.generateNextPolicy(t, 1)

	// Use fewer signers than needed (half of what's needed)
	insufficientSigners := setup.privKeys[:(len(setup.privKeys) / 10)]

	req := &types.UpdatePolicyRequest{
		NewPolicy:  testutils.BuildMultiSignedPolicy(t, nextPolicy.RawBytes(), insufficientSigners),
		PublicKeys: pubKeys,
	}
	_, err := setup.executeUpdatePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "threshold for updating policy not reached")
}

func TestUpdatePolicyNoSignatures(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	nextPolicy, pubKeys := setup.generateNextPolicy(t, 1)

	req := &types.UpdatePolicyRequest{
		NewPolicy: types.MultiSignedPolicy{
			PolicyBytes: nextPolicy.RawBytes(),
			Signatures:  [][]byte{},
		},
		PublicKeys: pubKeys,
	}

	_, err := setup.executeUpdatePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "threshold for updating policy not reached")
}

func TestUpdatePolicyInvalidSignatureLength(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	nextPolicy, pubKeys := setup.generateNextPolicy(t, 1)

	// Build request with valid signatures
	req := &types.UpdatePolicyRequest{
		NewPolicy:  testutils.BuildMultiSignedPolicy(t, nextPolicy.RawBytes(), setup.privKeys),
		PublicKeys: pubKeys,
	}

	// Corrupt one signature with invalid length
	req.NewPolicy.Signatures[0] = []byte{0x01, 0x02, 0x03}

	_, err := setup.executeUpdatePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid signature length")
}

func TestUpdatePolicyInvalidSignature(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	nextPolicy, pubKeys := setup.generateNextPolicy(t, 1)

	// Build request with valid signatures from all voters
	req := &types.UpdatePolicyRequest{
		NewPolicy:  testutils.BuildMultiSignedPolicy(t, nextPolicy.RawBytes(), setup.privKeys),
		PublicKeys: pubKeys,
	}

	// Create a signature from a non-voter (not in the voter set)
	// This ensures the signature is valid (recovery will work) but the
	// recovered address won't be in the voter list
	nonVoterPrivKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	// Sign the policy with the non-voter's key
	nonVoterSignedPolicy := testutils.BuildMultiSignedPolicy(t, nextPolicy.RawBytes(), []*ecdsa.PrivateKey{nonVoterPrivKey})
	nonVoterSig := nonVoterSignedPolicy.Signatures[0]

	// Replace one valid signature with the non-voter's signature
	req.NewPolicy.Signatures[0] = nonVoterSig

	_, err = setup.executeUpdatePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a voter")
}

func TestUpdatePolicyMismatchedPublicKeysCount(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	nextPolicy, _ := setup.generateNextPolicy(t, 1)

	// Provide fewer public keys than voters
	req := &types.UpdatePolicyRequest{
		NewPolicy:  testutils.BuildMultiSignedPolicy(t, nextPolicy.RawBytes(), setup.privKeys),
		PublicKeys: setup.pubKeys[:numVoters/2],
	}
	_, err := setup.executeUpdatePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "number of public keys and the number of voters do not match")
}

func TestUpdatePolicyMultipleUpdates(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	// First update
	nextPolicy1, pubKeys1 := setup.generateNextPolicy(t, 1)
	req1 := &types.UpdatePolicyRequest{
		NewPolicy:  testutils.BuildMultiSignedPolicy(t, nextPolicy1.RawBytes(), setup.privKeys),
		PublicKeys: pubKeys1,
	}
	_, err := setup.executeUpdatePolicy(t, req1)
	require.NoError(t, err)

	// Second update
	nextPolicy2, pubKeys2 := setup.generateNextPolicy(t, 2)
	req2 := &types.UpdatePolicyRequest{
		NewPolicy:  testutils.BuildMultiSignedPolicy(t, nextPolicy2.RawBytes(), setup.privKeys),
		PublicKeys: pubKeys2,
	}
	_, err = setup.executeUpdatePolicy(t, req2)
	require.NoError(t, err)

	// Verify final policy
	activePolicy, err := setup.pStorage.ActiveSigningPolicy()
	require.NoError(t, err)
	require.Equal(t, nextPolicy2.RewardEpochID, activePolicy.RewardEpochID)
}
