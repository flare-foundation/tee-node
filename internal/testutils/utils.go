package testutils

import (
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
	"github.com/stretchr/testify/require"

	ppolicy "github.com/flare-foundation/tee-node/pkg/policy"

	"github.com/flare-foundation/go-flare-common/pkg/contracts/relay"
	commonpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// GenerateRandomValidPolicyAndSigners produces a random policy alongside
// matching voter identities for tests.
func GenerateRandomValidPolicyAndSigners(t *testing.T, epochId uint32, randSeed int64, numVoters int) (*commonpolicy.SigningPolicy, []common.Address, []*ecdsa.PrivateKey, []types.PublicKey) {
	t.Helper()

	// Generate random voters and corresponding private keys
	voters, privKeys, pubKeysMap := GenerateRandomKeys(t, numVoters)

	initialPolicy := GenerateRandomPolicyData(t, epochId, voters, randSeed)

	pubKeys := make([]types.PublicKey, len(voters))
	for i, voter := range voters {
		pubKeys[i] = types.PubKeyToStruct(pubKeysMap[voter])
	}

	return initialPolicy, voters, privKeys, pubKeys
}

// BuildMultiSignedPolicy signs the provided policy bytes with all given voter
// keys and returns the multisigned wrapper.
func BuildMultiSignedPolicy(t *testing.T, policyBytes []byte, voterPrivKeys []*ecdsa.PrivateKey) types.MultiSignedPolicy {
	t.Helper()

	sigs := make([][]byte, 0, len(voterPrivKeys))

	hash := commonpolicy.Hash(policyBytes)
	for _, voterPrivKey := range voterPrivKeys {
		// sig, err := policy.SignNewSigningPolicy(policy.SigningPolicyHash(policyBytes), voterPrivKeys[i])
		sig, err := utils.Sign(hash, voterPrivKey)
		require.NoError(t, err)

		sigs = append(sigs, sig)
	}

	return types.MultiSignedPolicy{
		PolicyBytes: policyBytes,
		Signatures:  sigs,
	}
}

// GenerateRandomKeys creates a deterministic set of voters and key material for
// test policies.
func GenerateRandomKeys(t *testing.T, numVoters int) ([]common.Address, []*ecdsa.PrivateKey, map[common.Address]*ecdsa.PublicKey) {
	t.Helper()
	voters := make([]common.Address, numVoters)
	privKeys := make([]*ecdsa.PrivateKey, numVoters)
	pubKeys := make(map[common.Address]*ecdsa.PublicKey)

	for i := range numVoters {
		voterPrivKey, err := crypto.GenerateKey()
		require.NoError(t, err)

		voterPubKey := voterPrivKey.PublicKey

		privKeys[i] = voterPrivKey
		voters[i] = crypto.PubkeyToAddress(voterPubKey)
		pubKeys[voters[i]] = &voterPubKey
	}

	return voters, privKeys, pubKeys
}

const TotalWeight = 1<<16 - 1

// GenerateRandomPolicyData constructs a pseudo-random signing policy based on
// the provided voters and seed.
func GenerateRandomPolicyData(t *testing.T, rewardEpochID uint32, voters []common.Address, seed int64) *commonpolicy.SigningPolicy {
	t.Helper()

	// Use specific seed for deterministic results
	rgen := rand.New(rand.NewSource(seed)) //nolint:gosec // only used for tests

	startVotingRoundID := rgen.Uint32()

	threshold := uint16(TotalWeight / 2)
	randSeed := big.NewInt(rgen.Int63())
	weights := []uint16{}

	normalizedWeights := randomNormalizedArray(len(voters), seed)
	for _, w := range normalizedWeights {
		weights = append(weights, uint16(w*TotalWeight))
	}

	event := relay.RelaySigningPolicyInitialized{
		RewardEpochId:      big.NewInt(int64(rewardEpochID)),
		StartVotingRoundId: startVotingRoundID,
		Threshold:          threshold,
		Seed:               randSeed,
		Voters:             voters,
		Weights:            weights,
		Timestamp:          0,
	}
	policyBytes, err := encodeSigningPolicy(&event)
	require.NoError(t, err)

	event.SigningPolicyBytes = policyBytes

	policy := commonpolicy.NewSigningPolicy(&event, nil)

	return policy
}

// randomNormalizedArray generates an array of n random floats that sum to 1.
func randomNormalizedArray(n int, seed int64) []float64 {
	// Initialize random source with seed
	source := rand.NewSource(seed)
	r := rand.New(source) //nolint:gosec // only used for tests

	// Generate random numbers
	numbers := make([]float64, n)
	sum := 0.0

	for i := range n {
		// Generate random float between 0 and 1
		numbers[i] = r.Float64()
		sum += numbers[i]
	}

	// Normalize to sum to 1
	for i := range n {
		numbers[i] /= sum
	}

	return numbers
}

// GenerateAndSetInitialPolicy creates a mock policy, stores it in the provided
// storage, and returns the policy with its voters and keys.
func GenerateAndSetInitialPolicy(t *testing.T, ps *ppolicy.Storage, numVoters int, randSeed int64, epochID uint32) (*commonpolicy.SigningPolicy, []common.Address, []*ecdsa.PrivateKey) {
	t.Helper()

	// Generate random voters and corresponding private keys
	voters, privKeys, pubKeys := GenerateRandomKeys(t, numVoters)

	// Generate a random initial policy
	initialPolicy := GenerateRandomPolicyData(t, epochID, voters, randSeed)

	err := ps.SetInitialPolicy(initialPolicy, pubKeys)
	require.NoError(t, err)

	return initialPolicy, voters, privKeys
}

// encodeSigningPolicy serializes a relay signing policy into the byte layout
// expected by the TEE.
func encodeSigningPolicy(policy *relay.RelaySigningPolicyInitialized) ([]byte, error) {
	// Validation
	if policy == nil {
		return nil, fmt.Errorf("signing policy is undefined")
	}

	voters := policy.Voters
	if len(voters) > 65535 { // 2^16 - 1
		return nil, fmt.Errorf("too many signers")
	}
	if len(policy.Weights) != len(voters) {
		return nil, fmt.Errorf("number of voters and weights do not match")
	}

	// Validate reward epoch ID
	if policy.RewardEpochId.Int64() > 16777215 { // 2^24 - 1
		return nil, fmt.Errorf("reward epoch id out of range: %d", policy.RewardEpochId.Int64())
	}

	// Validate seed
	seedBytes := policy.Seed.Bytes()
	if len(seedBytes) > 32 {
		return nil, fmt.Errorf("seed value too large")
	}

	// Calculate total size
	// 2(numVoters) + 3(rewardEpoch) + 4(startVoting) + 2(threshold) + 32(seed) + len(voters)*(20+2)
	totalSize := 43 + len(voters)*22

	// Create result buffer
	result := make([]byte, totalSize)
	pos := 0

	// Write number of voters (2 bytes)
	binary.BigEndian.PutUint16(result[pos:], uint16(len(voters)))
	pos += 2

	// Write reward epoch ID (3 bytes)
	result[pos] = byte(policy.RewardEpochId.Int64() >> 16)
	result[pos+1] = byte(policy.RewardEpochId.Int64() >> 8)
	result[pos+2] = byte(policy.RewardEpochId.Int64())
	pos += 3

	// Write start voting round ID (4 bytes)
	binary.BigEndian.PutUint32(result[pos:], policy.StartVotingRoundId)
	pos += 4

	// Write threshold (2 bytes)
	binary.BigEndian.PutUint16(result[pos:], policy.Threshold)
	pos += 2

	// Write seed (32 bytes, pad if necessary)
	copy(result[pos+32-len(seedBytes):pos+32], seedBytes)
	pos += 32

	// Write voters and weights
	for i := range voters {
		// Write voter address (20 bytes)
		copy(result[pos:], voters[i][:])
		pos += 20

		// Write weight (2 bytes)
		binary.BigEndian.PutUint16(result[pos:], policy.Weights[i])
		pos += 2
	}

	return result, nil
}
