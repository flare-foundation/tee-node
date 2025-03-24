package policyservice

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"tee-node/pkg/policy"

	testutils "tee-node/tests"

	api "tee-node/api/types"
)

var numVoters int

func TestInitializePolicy(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test

	// Generate random voters and corresponding private keys
	numVoters = 100
	voters, privKeys := testutils.GenerateRandomVoters(numVoters)

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

	req := &api.InitializePolicyRequest{
		InitialPolicyBytes: initialPolicyBytes,
		NewPolicyRequests:  policySignaturesArray,
	}

	signingService := NewService()

	response, err := signingService.InitializePolicy(context.Background(), req)
	if err != nil {
		t.Errorf("Failed to initialize the policy: %v", err)
	}

	t.Logf("Response: %v\n", response)
}

// ! InitializePolicy Tests —————————————————————————————————————————————————————————————————————— //

// * Test initializing the policy after it has already been initialized  ----------------- //
func TestInitializingThePolicyTwice(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test

	epochId, randSeed := uint32(1), int64(12345)

	numVoters := 100
	_, initialPolicyBytes, voters, privKeys, err := testutils.GenerateRandomValidPolicyAndSigners(epochId, randSeed, numVoters)
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
		InitialPolicyBytes: initialPolicyBytes,
		NewPolicyRequests:  policySignaturesArray,
	}

	signingService := NewService()

	_, err = signingService.InitializePolicy(context.Background(), req)
	if err != nil {
		t.Errorf("Failed to initialize the policy: %v", err)
	}

	// & Try to initialize the policy again ------------------------------------------- //
	epochId2, randSeed2 := uint32(2), int64(54321)

	_, initialPolicyBytes2, _, _, err := testutils.GenerateRandomValidPolicyAndSigners(epochId2, randSeed2, numVoters)
	if err != nil {
		t.Errorf("Failed to generate the initial policy")
	}

	policySignaturesArray2, err := testutils.GenerateRandomMultiSignedPolicyArray(epochId2, randSeed2, voters, privKeys, numPolicies)
	if err != nil {
		t.Errorf("Failed to generate the policy signatures")
	}

	req2 := &api.InitializePolicyRequest{
		InitialPolicyBytes: initialPolicyBytes2,
		NewPolicyRequests:  policySignaturesArray2,
	}

	_, err = signingService.InitializePolicy(context.Background(), req2)

	// Convert error to gRPC status
	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected gRPC error status")
	}

	// Check error code
	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", st.Code())
	}

	// Check error message/description
	if st.Message() != "policy already initialized" {
		t.Errorf("expected 'policy already initialized', got %v", st.Message())
	}

}

// * Test sending a signature with a wrong reward epoch id, less or equal to a previos one -- //
func TestSendingInvalidReardEpochId(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test

	epochId, randSeed := uint32(10), int64(12345)

	numVoters := 100
	_, initialPolicyBytes, voters, privKeys, err := testutils.GenerateRandomValidPolicyAndSigners(epochId, randSeed, numVoters)
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
		InitialPolicyBytes: initialPolicyBytes,
		NewPolicyRequests:  policySignaturesArray,
	}

	signingService := NewService()

	_, err = signingService.InitializePolicy(context.Background(), req)
	require.Equal(t, err.Error(), "policy is not active")
}

// * Check that the request work only if requestPolicy is within config.ACTIVE_POLICY_COUNT of the active policy reward epoch id -- //
// TODO: CheckActive() function

// * Verify that that the function fails if the voter weight is less than the Threshold -- //
// TODO: Implement this test

// * Verify that if two signatures use the same public key, it throws an error -- //
// TODO:

// * Test should fail if we don't ser testutils.SetInitialPolicyHash(initialPolicyBytes) in the function -- //

// ! SignNewPolicy Tests ———————————————————————————————————————————————————————————————————————— //

// * verify the policy with invalid reward epoch id (should fail)

// * Verify that if two signatures from the same request use the same public key, it throws a 'Attempted double signing' error -- //

// * Verify that if two signatures from different request use the same public key, it throws a 'Attempted double signing' error -- //

// * Test that the voter weight is incremented correctly (Check that the policy only gets updated when the threshold is reached) -- //

// * UTILS ================================================================================================ * //
// * ====================================================================================================== * //
