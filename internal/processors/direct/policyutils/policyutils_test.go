package policyutils

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/types"
)

var numVoters int

func TestInitializePolicy(t *testing.T) {
	_, pStorage, _ := testutils.Setup(t)

	// Generate random voters and corresponding private keys
	numVoters = 100
	voters, _, pubKeysMap := testutils.GenerateRandomKeys(numVoters)
	// Generate a random initial policy
	randSeed := int64(12345)
	epochId := uint32(1)
	initialPolicy, err := testutils.GenerateRandomPolicyData(epochId, voters, randSeed)
	require.NoError(t, err)

	pubKeys := make([]types.PublicKey, len(voters))
	for i, voter := range voters {
		pubKeys[i] = types.PubKeyToStruct(pubKeysMap[voter])
	}

	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: initialPolicy.RawBytes(),
		PublicKeys:         pubKeys,
	}

	message, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to build the mock initialize policy request: %v", err)
	}

	proc := Processor{pStorage}

	_, err = proc.InitializePolicy(&types.DirectInstruction{Message: message})
	if err != nil {
		t.Errorf("Failed to initialize the policy: %v", err)
	}
}

func TestInitializingThePolicyTwice(t *testing.T) {
	_, pStorage, _ := testutils.Setup(t)

	epochId, randSeed := uint32(1), int64(12345)

	numVoters := 100
	initialPolicy, _, _, pubKeys, err := testutils.GenerateRandomValidPolicyAndSigners(epochId, randSeed, numVoters)
	if err != nil {
		t.Errorf("Failed to generate the initial policy")
	}

	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: initialPolicy.RawBytes(),
		PublicKeys:         pubKeys,
	}
	message, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to build the mock initialize policy request: %v", err)
	}

	proc := Processor{pStorage}

	_, err = proc.InitializePolicy(&types.DirectInstruction{Message: message})
	if err != nil {
		t.Errorf("Failed to initialize the policy: %v", err)
	}

	// & Try to initialize the policy again ------------------------------------------- //
	epochId2, randSeed2 := uint32(2), int64(54321)

	initialPolicy2, _, _, pubKeys2, err := testutils.GenerateRandomValidPolicyAndSigners(epochId2, randSeed2, numVoters)
	if err != nil {
		t.Errorf("Failed to generate the initial policy")
	}

	req2 := &types.InitializePolicyRequest{
		InitialPolicyBytes: initialPolicy2.RawBytes(),
		PublicKeys:         pubKeys2,
	}
	message2, err := json.Marshal(req2)
	if err != nil {
		t.Fatalf("Failed to build the mock initialize policy request: %v", err)
	}
	_, err = proc.InitializePolicy(&types.DirectInstruction{Message: message2})
	if err.Error() != "policy already initialized" {
		t.Errorf("expected 'policy already initialized', got %v", err)
	}
}

func TestUpdatePolicy(t *testing.T) {
	_, pStorage, _ := testutils.Setup(t)

	// Generate random voters and corresponding private keys
	numVoters = 100
	voters, privKeys, pubKeysMap := testutils.GenerateRandomKeys(numVoters)
	// Generate a random initial policy
	randSeed := int64(12345)
	epochId := uint32(1)
	initialPolicy, err := testutils.GenerateRandomPolicyData(epochId, voters, randSeed)
	require.NoError(t, err)

	// Set the initial policy hash in the config
	err = pStorage.SetInitialPolicy(initialPolicy, pubKeysMap)
	require.NoError(t, err)

	epochId++
	randSeed++
	nextPolicy, err := testutils.GenerateRandomPolicyData(epochId, voters, randSeed)
	require.NoError(t, err)

	policySignatures := testutils.BuildMultiSignedPolicy(nextPolicy.RawBytes(), privKeys)

	pubKeys := make([]types.PublicKey, len(voters))
	for i, voter := range voters {
		pubKeys[i] = types.PubKeyToStruct(pubKeysMap[voter])
	}

	updatePolicyRequest := types.UpdatePolicyRequest{
		NewPolicy:  policySignatures,
		PublicKeys: pubKeys,
	}
	updatePolicyRequestBytes, err := json.Marshal(updatePolicyRequest)
	require.NoError(t, err)
	proc := Processor{pStorage}

	_, err = proc.UpdatePolicy(&types.DirectInstruction{Message: updatePolicyRequestBytes})
	require.NoError(t, err)

	// todo: check new policy
}
