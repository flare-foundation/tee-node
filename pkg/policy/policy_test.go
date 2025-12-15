package policy_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test constants
const (
	testEpochID1 = uint32(1)
	testEpochID2 = uint32(2)
	testEpochID3 = uint32(3)
	numVoters    = 100
)

var testSeed int64

func init() {
	n, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		panic("no randomness")
	}
	testSeed = n.Int64()
}

// setupTestStorage creates a test storage with initial policy
func setupTestStorage(t *testing.T) (*policy.Storage, common.Hash) {
	t.Helper()

	storage := policy.InitializeStorage()

	// Generate test data
	voters, _, pubKeysMap := testutils.GenerateRandomKeys(t, numVoters)
	initialPolicy := testutils.GenerateRandomPolicyData(t, testEpochID1, voters, testSeed)

	// Set initial policy
	err := storage.SetInitialPolicy(initialPolicy, pubKeysMap)
	require.NoError(t, err)

	return storage, common.Hash(initialPolicy.Hash())
}

func TestInitializeStorage(t *testing.T) {
	storage := policy.InitializeStorage()

	initialID, initialHash, activeID, activeHash := storage.Info()

	assert.NotNil(t, storage)
	assert.Equal(t, uint32(0), initialID)
	assert.Equal(t, common.Hash{}, initialHash)
	assert.Equal(t, uint32(0), activeID)
	assert.Equal(t, common.Hash{}, activeHash)
}

func TestSetInitialPolicy_Success(t *testing.T) {
	storage := policy.InitializeStorage()

	// Generate test data
	voters, _, pubKeysMap := testutils.GenerateRandomKeys(t, numVoters)
	initialPolicy := testutils.GenerateRandomPolicyData(t, testEpochID1, voters, testSeed)

	// Set initial policy
	err := storage.SetInitialPolicy(initialPolicy, pubKeysMap)
	require.NoError(t, err)

	initialID, initialHash, activeID, activeHash := storage.Info()

	// Verify state
	assert.Equal(t, testEpochID1, initialID)
	assert.Equal(t, common.Hash(initialPolicy.Hash()), initialHash)
	assert.Equal(t, testEpochID1, activeID)
	assert.Equal(t, common.Hash(initialPolicy.Hash()), activeHash)
}

func TestSetInitialPolicy_DoubleInitialization(t *testing.T) {
	storage, _ := setupTestStorage(t)

	// Attempt to set initial policy again
	voters, _, pubKeysMap := testutils.GenerateRandomKeys(t, numVoters)
	secondPolicy := testutils.GenerateRandomPolicyData(t, testEpochID2, voters, testSeed+1)

	err := storage.SetInitialPolicy(secondPolicy, pubKeysMap)
	assert.Error(t, err)
	assert.Equal(t, "signing policy already initialized", err.Error())
}

func TestActiveSigningPolicy_Success(t *testing.T) {
	storage, initialHash := setupTestStorage(t)

	policy, err := storage.ActiveSigningPolicy()
	require.NoError(t, err)

	assert.NotNil(t, policy)
	assert.Equal(t, testEpochID1, policy.RewardEpochID)
	assert.Equal(t, initialHash, common.Hash(policy.Hash()))
}

func TestActiveSigningPolicy_NotInitialized(t *testing.T) {
	storage := policy.InitializeStorage()

	policy, err := storage.ActiveSigningPolicy()
	assert.Error(t, err)
	assert.Nil(t, policy)
	assert.Equal(t, "signing policy not initialized", err.Error())
}

func TestInitialPolicyIDAndHash(t *testing.T) {
	storage, initialHash := setupTestStorage(t)

	id, hash := storage.InitialPolicyIDAndHash()

	assert.Equal(t, testEpochID1, id)
	assert.Equal(t, initialHash, hash)
}

func TestSigningPolicy_Success(t *testing.T) {
	storage, initialHash := setupTestStorage(t)

	policy, err := storage.SigningPolicy(testEpochID1)
	require.NoError(t, err)

	assert.NotNil(t, policy)
	assert.Equal(t, testEpochID1, policy.RewardEpochID)
	assert.Equal(t, initialHash, common.Hash(policy.Hash()))
}

func TestSigningPolicy_NotFound(t *testing.T) {
	storage, _ := setupTestStorage(t)

	policy, err := storage.SigningPolicy(testEpochID2)
	assert.Error(t, err)
	assert.Nil(t, policy)
	assert.Equal(t, "policy of the given reward epoch not in the storage", err.Error())
}

func TestSetActiveSigningPolicy_Success(t *testing.T) {
	storage, _ := setupTestStorage(t)

	// Create a new policy
	voters, _, _ := testutils.GenerateRandomKeys(t, numVoters)
	newPolicy := testutils.GenerateRandomPolicyData(t, testEpochID2, voters, testSeed+1)

	err := storage.SetActiveSigningPolicy(newPolicy)
	require.NoError(t, err)

	// Verify the new policy is active
	activePolicy, err := storage.ActiveSigningPolicy()
	require.NoError(t, err)
	assert.Equal(t, testEpochID2, activePolicy.RewardEpochID)
	assert.Equal(t, common.Hash(newPolicy.Hash()), common.Hash(activePolicy.Hash()))

	// Verify the new policy is stored in signingPolicies
	epcoh2Policy, err := storage.SigningPolicy(testEpochID2)
	require.NoError(t, err)
	assert.Equal(t, testEpochID2, epcoh2Policy.RewardEpochID)
	assert.Equal(t, common.Hash(newPolicy.Hash()), common.Hash(epcoh2Policy.Hash()))
}

func TestSetActiveSigningPolicy_NotInitialized(t *testing.T) {
	storage := policy.InitializeStorage()

	voters, _, _ := testutils.GenerateRandomKeys(t, numVoters)
	policy := testutils.GenerateRandomPolicyData(t, testEpochID1, voters, testSeed)

	err := storage.SetActiveSigningPolicy(policy)
	assert.Error(t, err)
	assert.Equal(t, "signing policy not initialized yet", err.Error())
}

func TestSetActiveSigningPolicyPublicKeys_Success(t *testing.T) {
	storage, _ := setupTestStorage(t)

	// Create new public keys
	voters, _, newPubKeysMap := testutils.GenerateRandomKeys(t, numVoters)
	policy := testutils.GenerateRandomPolicyData(t, testEpochID1, voters, testSeed)

	err := storage.SetActiveSigningPolicy(policy)
	assert.NoError(t, err)

	err = storage.SetActiveSigningPolicyPublicKeys(newPubKeysMap)
	require.NoError(t, err)

	activePublicKeys, err := storage.ActiveSigningPolicyPublicKeys()
	require.NoError(t, err)

	for address, pubKey := range newPubKeysMap {
		assert.Contains(t, activePublicKeys, pubKey)
		assert.Equal(t, address, crypto.PubkeyToAddress(*pubKey))
	}
}

func TestSetActiveSigningPolicyPublicKeys_NotInitialized(t *testing.T) {
	storage := policy.InitializeStorage()

	_, _, pubKeysMap := testutils.GenerateRandomKeys(t, numVoters)

	err := storage.SetActiveSigningPolicyPublicKeys(pubKeysMap)
	assert.Error(t, err)
	assert.Equal(t, "signing policy not initialized yet", err.Error())
}

func TestActiveSigningPolicyPublicKeys_MissingAddress(t *testing.T) {
	storage, _ := setupTestStorage(t)

	// Create a public key map with missing addresses
	incompleteMap := make(map[common.Address]*ecdsa.PublicKey)
	err := storage.SetActiveSigningPolicyPublicKeys(incompleteMap)
	assert.NoError(t, err)

	pubKeys, err := storage.ActiveSigningPolicyPublicKeys()
	assert.Error(t, err)
	assert.Nil(t, pubKeys)
	assert.Equal(t, "address not in policy public key map, internal error", err.Error())
}

func TestWeightOfSigners_Success(t *testing.T) {
	storage, _ := setupTestStorage(t)
	activePolicy, err := storage.ActiveSigningPolicy()
	require.NoError(t, err)

	voters := activePolicy.Voters.Voters()

	// Test with all signers
	weight := policy.WeightOfSigners(voters, activePolicy)
	assert.Equal(t, weight, activePolicy.Voters.TotalWeight)

	// Test with subset of signers
	subset := voters[:2]
	subsetWeight := policy.WeightOfSigners(subset, activePolicy)
	assert.Less(t, subsetWeight, weight)

	// Test with empty signers
	emptyWeight := policy.WeightOfSigners([]common.Address{}, activePolicy)
	assert.Equal(t, uint16(0), emptyWeight)
}

func TestWeightOfSigners_DuplicateSigners(t *testing.T) {
	storage, _ := setupTestStorage(t)
	activePolicy, err := storage.ActiveSigningPolicy()
	require.NoError(t, err)

	voters := activePolicy.Voters.Voters()

	// Create slice with duplicate signers
	duplicates := []common.Address{voters[0], voters[1], voters[0], voters[1]}

	// Weight should be calculated only once per unique signer
	uniqueWeight := policy.WeightOfSigners(voters[:2], activePolicy)
	duplicateWeight := policy.WeightOfSigners(duplicates, activePolicy)

	assert.Equal(t, uniqueWeight, duplicateWeight)
}

func TestDestroyState(t *testing.T) {
	storage, _ := setupTestStorage(t)

	// Verify storage is initialized
	_, err := storage.ActiveSigningPolicy()
	require.NoError(t, err)

	// Destroy state
	storage.DestroyState()

	initialID, initialHash, activeID, activeHash := storage.Info()

	assert.NotNil(t, storage)
	assert.Equal(t, uint32(0), initialID)
	assert.Equal(t, common.Hash{}, initialHash)
	assert.Equal(t, uint32(0), activeID)
	assert.Equal(t, common.Hash{}, activeHash)

	_, err = storage.ActiveSigningPolicy()
	assert.Error(t, err)
	assert.Equal(t, "signing policy not initialized", err.Error())
}

func TestConcurrentAccess(t *testing.T) {
	storage, _ := setupTestStorage(t)

	const numGoroutines = 100
	var wg sync.WaitGroup

	// Test concurrent reads
	for range numGoroutines {
		wg.Go(func() {
			// Concurrent read operations should be safe
			_, err := storage.ActiveSigningPolicy()
			assert.NoError(t, err)

			_, err = storage.ActiveSigningPolicyPublicKeys()
			assert.NoError(t, err)

			storage.Info()
		})
	}

	wg.Wait()
}

func TestPolicyLifecycle_CompleteFlow(t *testing.T) {
	storage := policy.InitializeStorage()

	// Step 1: Initialize with first policy
	voters1, _, pubKeysMap1 := testutils.GenerateRandomKeys(t, numVoters)
	policy1 := testutils.GenerateRandomPolicyData(t, testEpochID1, voters1, testSeed)

	err := storage.SetInitialPolicy(policy1, pubKeysMap1)
	require.NoError(t, err)

	// Verify initial state
	activePolicy, err := storage.ActiveSigningPolicy()
	require.NoError(t, err)
	assert.Equal(t, testEpochID1, activePolicy.RewardEpochID)
	assert.Equal(t, common.Hash(policy1.Hash()), common.Hash(activePolicy.Hash()))

	// Step 2: Update to second policy
	voters2, _, pubKeysMap2 := testutils.GenerateRandomKeys(t, numVoters)
	policy2 := testutils.GenerateRandomPolicyData(t, testEpochID2, voters2, testSeed+1)
	require.NoError(t, err)

	err = storage.SetActiveSigningPolicy(policy2)
	require.NoError(t, err)
	err = storage.SetActiveSigningPolicyPublicKeys(pubKeysMap2)
	require.NoError(t, err)

	// Verify update
	activePolicy, err = storage.ActiveSigningPolicy()
	require.NoError(t, err)
	assert.Equal(t, testEpochID2, activePolicy.RewardEpochID)
	assert.Equal(t, common.Hash(policy2.Hash()), common.Hash(activePolicy.Hash()))

	// Step 3: Verify both policies are stored
	_, err = storage.SigningPolicy(testEpochID1)
	require.NoError(t, err)
	_, err = storage.SigningPolicy(testEpochID2)
	require.NoError(t, err)

	// Step 4: Verify info reflects current state
	initialID, initialHash, activeID, activeHash := storage.Info()
	assert.Equal(t, testEpochID1, initialID)
	assert.Equal(t, testEpochID2, activeID)
	assert.NotEqual(t, initialHash, activeHash)
	assert.Equal(t, common.Hash(policy2.Hash()), activeHash)
}
