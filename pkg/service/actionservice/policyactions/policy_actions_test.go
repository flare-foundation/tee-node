package policyactions

import (
	"testing"

	"github.com/stretchr/testify/require"

	"tee-node/pkg/policy"

	testutils "tee-node/tests"

	api "tee-node/api/types"
)

var numVoters int

func TestInitializePolicy(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test

	// Generate random voters and corresponding private keys
	numVoters = 100
	voters, privKeys, pubKeysMap := testutils.GenerateRandomVoters(numVoters)
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
	policySignaturesArray := []api.MultiSignedPolicy{}

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

	pubKeys := make([]api.ECDSAPublicKey, len(voters))
	for i, voter := range voters {
		pubKeys[i] = api.PubKeyToBytes(pubKeysMap[voter])
	}

	req := &api.InitializePolicyRequest{
		InitialPolicyBytes:     initialPolicyBytes,
		NewPolicyRequests:      policySignaturesArray,
		LatestPolicyPublicKeys: pubKeys,
	}
	action, err := testutils.BuildMockInitializePolicyAction(req)
	if err != nil {
		t.Fatalf("Failed to build the mock initialize policy action: %v", err)
	}
	err = InitializePolicy(action.Data.Message)
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

	req := &api.InitializePolicyRequest{
		InitialPolicyBytes:     initialPolicyBytes,
		NewPolicyRequests:      policySignaturesArray,
		LatestPolicyPublicKeys: pubKeys,
	}
	action, err := testutils.BuildMockInitializePolicyAction(req)
	if err != nil {
		t.Fatalf("Failed to build the mock initialize policy action: %v", err)
	}
	err = InitializePolicy(action.Data.Message)
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

	req2 := &api.InitializePolicyRequest{
		InitialPolicyBytes:     initialPolicyBytes2,
		NewPolicyRequests:      policySignaturesArray2,
		LatestPolicyPublicKeys: pubKeys,
	}
	action2, err := testutils.BuildMockInitializePolicyAction(req2)
	if err != nil {
		t.Fatalf("Failed to build the mock initialize policy action: %v", err)
	}
	err = InitializePolicy(action2.Data.Message)
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

	req := &api.InitializePolicyRequest{
		InitialPolicyBytes:     initialPolicyBytes,
		NewPolicyRequests:      policySignaturesArray,
		LatestPolicyPublicKeys: pubKeys,
	}

	action, err := testutils.BuildMockInitializePolicyAction(req)
	if err != nil {
		t.Fatalf("Failed to build the mock initialize policy action: %v", err)
	}
	err = InitializePolicy(action.Data.Message)
	require.Equal(t, err.Error(), "policy is not active")
}
