package policyactions

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"tee-node/pkg/tee/node"
	"tee-node/pkg/tee/policy"

	testutils "tee-node/testutils"

	"tee-node/api/types"
)

var numVoters int

func TestInitializePolicy(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test

	// Generate random voters and corresponding private keys
	numVoters = 100
	voters, privKeys, pubKeysMap := testutils.GenerateRandomKeys(numVoters)
	// Generate a random initial policy
	randSeed := int64(12345)
	epochId := uint32(1)
	initialPolicy := testutils.GenerateRandomPolicyData(epochId, voters, randSeed)

	initialPolicyBytes, err := policy.EncodeSigningPolicy(&initialPolicy)
	if err != nil {
		t.Errorf("Failed to encode the policy: %v", err)
	}

	// Set the initial policy hash in the config
	testutils.SetMockInitialPolicy(initialPolicyBytes)

	// Generate a few more policies and their signatures
	policySignaturesArray := []types.MultiSignedPolicy{}

	numPolicies := 5 // Number of policies to generate
	for i := 0; i < numPolicies; i++ {
		epochId++
		randSeed++
		nextPolicy := testutils.GenerateRandomPolicyData(epochId, voters, randSeed)

		nextPolicyBytes, err := policy.EncodeSigningPolicy(&nextPolicy)
		if err != nil {
			t.Errorf("Failed to encode the policy %v", err)
		}

		policySignatures := testutils.BuildMultiSignedPolicy(nextPolicyBytes, privKeys)
		policySignaturesArray = append(policySignaturesArray, policySignatures)
	}

	pubKeys := make([]types.ECDSAPublicKey, len(voters))
	for i, voter := range voters {
		pubKeys[i] = types.PubKeyToStruct(pubKeysMap[voter])
	}

	req := &types.InitializePolicyRequest{
		InitialPolicyBytes:     initialPolicyBytes,
		Policies:               policySignaturesArray,
		LatestPolicyPublicKeys: pubKeys,
	}

	message, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to build the mock initialize policy request: %v", err)
	}
	err = InitializePolicy(message)
	if err != nil {
		t.Errorf("Failed to initialize the policy: %v", err)
	}
}

func TestInitializingThePolicyTwice(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test

	epochId, randSeed := uint32(1), int64(12345)

	numVoters := 100
	_, initialPolicyBytes, voters, privKeys, pubKeys, err := testutils.GenerateRandomValidPolicyAndSigners(epochId, randSeed, numVoters)
	if err != nil {
		t.Errorf("Failed to generate the initial policy")
	}

	// Set the initial policy hash in the config
	testutils.SetMockInitialPolicy(initialPolicyBytes)

	numPolicies := 1
	policySignaturesArray, err := testutils.GenerateRandomMultiSignedPolicyArray(epochId, randSeed, voters, privKeys, numPolicies)
	if err != nil {
		t.Errorf("Failed to generate the policy signatures")
	}

	req := &types.InitializePolicyRequest{
		InitialPolicyBytes:     initialPolicyBytes,
		Policies:               policySignaturesArray,
		LatestPolicyPublicKeys: pubKeys,
	}
	message, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to build the mock initialize policy request: %v", err)
	}
	err = InitializePolicy(message)
	if err != nil {
		t.Errorf("Failed to initialize the policy: %v", err)
	}

	// & Try to initialize the policy again ------------------------------------------- //
	epochId2, randSeed2 := uint32(2), int64(54321)

	_, initialPolicyBytes2, _, _, _, err := testutils.GenerateRandomValidPolicyAndSigners(epochId2, randSeed2, numVoters)
	if err != nil {
		t.Errorf("Failed to generate the initial policy")
	}

	policySignaturesArray2, err := testutils.GenerateRandomMultiSignedPolicyArray(epochId2, randSeed2, voters, privKeys, numPolicies)
	if err != nil {
		t.Errorf("Failed to generate the policy signatures")
	}

	req2 := &types.InitializePolicyRequest{
		InitialPolicyBytes:     initialPolicyBytes2,
		Policies:               policySignaturesArray2,
		LatestPolicyPublicKeys: pubKeys,
	}
	message2, err := json.Marshal(req2)
	if err != nil {
		t.Fatalf("Failed to build the mock initialize policy request: %v", err)
	}
	err = InitializePolicy(message2)
	if err.Error() != "policy already initialized" {
		t.Errorf("expected 'policy already initialized', got %v", err)
	}
}

func TestSendingInvalidReardEpochId(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test

	epochId, randSeed := uint32(10), int64(12345)

	numVoters := 100
	_, initialPolicyBytes, voters, privKeys, pubKeys, err := testutils.GenerateRandomValidPolicyAndSigners(epochId, randSeed, numVoters)
	if err != nil {
		t.Errorf("Failed to generate the initial policy")
	}

	// Set the initial policy hash in the config
	testutils.SetMockInitialPolicy(initialPolicyBytes)

	numPolicies := 1

	// Decrease the reward epoch id to test if the policy is rejected
	policySignaturesArray, err := testutils.GenerateRandomMultiSignedPolicyArray(epochId-1, randSeed, voters, privKeys, numPolicies)
	if err != nil {
		t.Errorf("Failed to generate the policy signatures")
	}

	req := &types.InitializePolicyRequest{
		InitialPolicyBytes:     initialPolicyBytes,
		Policies:               policySignaturesArray,
		LatestPolicyPublicKeys: pubKeys,
	}

	message, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to build the mock initialize policy request: %v", err)
	}
	err = InitializePolicy(message)
	require.Equal(t, err.Error(), "policy is not active")
}

func TestUpdatePolicy(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test

	err := node.InitNode()
	require.NoError(t, err)

	// Generate random voters and corresponding private keys
	numVoters = 100
	voters, privKeys, pubKeysMap := testutils.GenerateRandomKeys(numVoters)
	// Generate a random initial policy
	randSeed := int64(12345)
	epochId := uint32(1)
	initialPolicy := testutils.GenerateRandomPolicyData(epochId, voters, randSeed)

	// Set the initial policy hash in the config
	testutils.SetInitialPolicy(&initialPolicy, pubKeysMap)

	epochId++
	randSeed++
	nextPolicy := testutils.GenerateRandomPolicyData(epochId, voters, randSeed)

	nextPolicyBytes, err := policy.EncodeSigningPolicy(&nextPolicy)
	if err != nil {
		t.Errorf("Failed to encode the policy %v", err)
	}

	policySignatures := testutils.BuildMultiSignedPolicy(nextPolicyBytes, privKeys)

	pubKeys := make([]types.ECDSAPublicKey, len(voters))
	for i, voter := range voters {
		pubKeys[i] = types.PubKeyToStruct(pubKeysMap[voter])
	}

	updatePolicyRequest := types.UpdatePolicyRequest{
		NewPolicy:              policySignatures,
		LatestPolicyPublicKeys: pubKeys,
	}
	updatePolicyRequestBytes, err := json.Marshal(updatePolicyRequest)
	require.NoError(t, err)

	err = UpdatePolicy(updatePolicyRequestBytes)
	require.NoError(t, err)

	// todo: check new policy
}
