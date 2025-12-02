package testutils

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net/http"

	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	ppolicy "github.com/flare-foundation/tee-node/pkg/policy"

	"github.com/flare-foundation/go-flare-common/pkg/contracts/relay"
	commonpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// EncodeSigningPolicy serializes a relay signing policy into the byte layout
// expected by the TEE.
func EncodeSigningPolicy(policy *relay.RelaySigningPolicyInitialized) ([]byte, error) {
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
	for i := 0; i < len(voters); i++ {
		// Write voter address (20 bytes)
		copy(result[pos:], voters[i][:])
		pos += 20

		// Write weight (2 bytes)
		binary.BigEndian.PutUint16(result[pos:], policy.Weights[i])
		pos += 2
	}

	return result, nil
}

// GenerateRandomValidPolicyAndSigners produces a random policy alongside
// matching voter identities for tests.
func GenerateRandomValidPolicyAndSigners(epochId uint32, randSeed int64, numVoters int) (*commonpolicy.SigningPolicy, []common.Address, []*ecdsa.PrivateKey, []types.PublicKey, error) {
	// Generate random voters and corresponding private keys
	voters, privKeys, pubKeysMap := GenerateRandomKeys(numVoters)

	initialPolicy, err := GenerateRandomPolicyData(epochId, voters, randSeed)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	pubKeys := make([]types.PublicKey, len(voters))
	for i, voter := range voters {
		pubKeys[i] = types.PubKeyToStruct(pubKeysMap[voter])
	}

	return initialPolicy, voters, privKeys, pubKeys, nil
}

// func GenerateRandomMultiSignedPolicyArray(epochId uint32, randSeed int64, voters []common.Address, privKeys []*ecdsa.PrivateKey, numPolicies int) ([]types.MultiSignedPolicy, error) {
// 	// Generate a few more policies and their signatures
// 	multiSignedPolicyArray := []types.MultiSignedPolicy{}

// 	_epochId, _randSeed := epochId, randSeed

// 	for range numPolicies {
// 		_epochId++
// 		_randSeed++
// 		nextPolicy := GenerateRandomPolicyData(_epochId, voters, _randSeed)

// 		policySignatures := BuildMultiSignedPolicy(nextPolicy.RawBytes(), privKeys)
// 		multiSignedPolicyArray = append(multiSignedPolicyArray, policySignatures)
// 	}

// 	return multiSignedPolicyArray, nil
// }

// BuildMultiSignedPolicy signs the provided policy bytes with all given voter
// keys and returns the multisigned wrapper.
func BuildMultiSignedPolicy(policyBytes []byte, voterPrivKeys []*ecdsa.PrivateKey) types.MultiSignedPolicy {
	sigs := make([][]byte, 0, len(voterPrivKeys))

	hash := commonpolicy.Hash(policyBytes)
	for _, voterPrivKey := range voterPrivKeys {
		// sig, err := policy.SignNewSigningPolicy(policy.SigningPolicyHash(policyBytes), voterPrivKeys[i])
		sig, err := utils.Sign(hash, voterPrivKey)
		if err != nil {
			panic(err)
		}
		sigs = append(sigs, sig)
	}

	return types.MultiSignedPolicy{
		PolicyBytes: policyBytes,
		Signatures:  sigs,
	}
}

// GenerateRandomKeys creates a deterministic set of voters and key material for
// test policies.
func GenerateRandomKeys(numVoters int) ([]common.Address, []*ecdsa.PrivateKey, map[common.Address]*ecdsa.PublicKey) {
	voters := make([]common.Address, numVoters)
	privKeys := make([]*ecdsa.PrivateKey, numVoters)
	pubKeys := make(map[common.Address]*ecdsa.PublicKey)

	for i := range numVoters {
		voterPrivKey, err := crypto.GenerateKey()
		if err != nil {
			panic(err)
		}
		voterPubKey := voterPrivKey.PublicKey

		privKeys[i] = voterPrivKey
		voters[i] = crypto.PubkeyToAddress(voterPubKey)
		pubKeys[voters[i]] = &voterPubKey
	}

	return voters, privKeys, pubKeys
}

// GetSignerWeight returns the voting weight of the provided public key for the
// supplied policy.
func GetSignerWeight(pubKey *ecdsa.PublicKey, policy *commonpolicy.SigningPolicy) uint16 {
	// Convert the public key to an Ethereum address
	address := crypto.PubkeyToAddress(*pubKey)

	return policy.Voters.VoterWeightForAddress(address)
}

const TotalWeight = 1<<16 - 1

// GenerateRandomPolicyData constructs a pseudo-random signing policy based on
// the provided voters and seed.
func GenerateRandomPolicyData(rewardEpochID uint32, voters []common.Address, seed int64) (*commonpolicy.SigningPolicy, error) {
	// Use specific seed for deterministic results
	rgen := rand.New(rand.NewSource(seed)) //nolint:gosec // only used for tests

	startVotingRoundID := rgen.Uint32()

	threshold := uint16(TotalWeight / 2)
	randSeed := big.NewInt(rgen.Int63())
	weights := []uint16{}

	normalizedWeights := RandomNormalizedArray(len(voters), seed)
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
	policyBytes, err := EncodeSigningPolicy(&event)
	if err != nil {
		return nil, err
	}
	event.SigningPolicyBytes = policyBytes

	policy := commonpolicy.NewSigningPolicy(&event, nil)

	return policy, nil
}

// GetThresholdReachedVoterIndex returns the index at which the accumulated
// voter weight crosses the policy threshold.
func GetThresholdReachedVoterIndex(nextPolicy *commonpolicy.SigningPolicy, voterPrivKeys []*ecdsa.PrivateKey) (int, uint16) {
	var weightSum uint16 = 0
	for i := range voterPrivKeys {
		pubKey := voterPrivKeys[i].PublicKey
		voterWeight := GetSignerWeight(&pubKey, nextPolicy)

		weightSum += voterWeight

		if weightSum >= nextPolicy.Threshold {
			return i, weightSum
		}
	}

	return len(voterPrivKeys) - 1, weightSum
}

// RandomNormalizedArray generates an array of n random floats that sum to 1.
func RandomNormalizedArray(n int, seed int64) []float64 {
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
	for i := 0; i < n; i++ {
		numbers[i] /= sum
	}

	return numbers
}

// GenerateAndSetInitialPolicy creates a mock policy, stores it in the provided
// storage, and returns the policy with its voters and keys.
func GenerateAndSetInitialPolicy(ps *ppolicy.Storage, numVoters int, randSeed int64, epochID uint32) (*commonpolicy.SigningPolicy, []common.Address, []*ecdsa.PrivateKey, error) {
	// Generate random voters and corresponding private keys
	voters, privKeys, pubKeys := GenerateRandomKeys(numVoters)

	// Generate a random initial policy
	initialPolicy, err := GenerateRandomPolicyData(epochID, voters, randSeed)
	if err != nil {
		return nil, nil, nil, err
	}

	err = ps.SetInitialPolicy(initialPolicy, pubKeys)
	return initialPolicy, voters, privKeys, err
}

// Providers represents a group of voters with private keys.
type Providers struct {
	Voters   []common.Address
	PrivKeys []*ecdsa.PrivateKey
}

// ProvidersJSON is the struct used for JSON serialization.
type ProvidersJSON struct {
	Voters   []string `json:"voters"`   // Ethereum addresses as hex strings
	PrivKeys []string `json:"privKeys"` // Private keys as hex strings
}

// MarshalProviders converts the Providers struct to a JSON payload.
func MarshalProviders(providers *Providers) ([]byte, error) {
	var voters []string
	for _, v := range providers.Voters {
		voters = append(voters, v.Hex()) // Convert addresses to hex string
	}

	var privKeys []string
	for _, key := range providers.PrivKeys {
		privKeys = append(privKeys, key.D.Text(16)) // Store private key D as hex string
	}

	jsonData, err := json.Marshal(ProvidersJSON{
		Voters:   voters,
		PrivKeys: privKeys,
	})
	return jsonData, err
}

// UnmarshalProviders reconstructs Providers from the JSON payload.
func UnmarshalProviders(jsonData []byte) (*Providers, error) {
	var providersJSON ProvidersJSON
	err := json.Unmarshal(jsonData, &providersJSON)
	if err != nil {
		return nil, err
	}

	var voters []common.Address
	for _, v := range providersJSON.Voters {
		voters = append(voters, common.HexToAddress(v))
	}

	var privKeys []*ecdsa.PrivateKey
	for _, keyStr := range providersJSON.PrivKeys {
		d := new(big.Int)
		d.SetString(keyStr, 16) // Convert hex string back to big.Int

		privKey := crypto.ToECDSAUnsafe(d.Bytes())

		privKeys = append(privKeys, privKey)
	}

	return &Providers{Voters: voters, PrivKeys: privKeys}, nil
}

// Post marshals the request, sends it as JSON, and decodes the response into R.
func Post[R any](url string, req any) (R, error) {
	requestBody, err := json.Marshal(req)
	if err != nil {
		return *new(R), err
	}
	res, err := http.Post(url, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return *new(R), err
	}
	defer res.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return *new(R), err
	}
	if res.StatusCode != http.StatusOK {
		return *new(R), fmt.Errorf("unexpected status code: %d, response: %s", res.StatusCode, string(body))
	}
	var response R
	err = json.Unmarshal(body, &response)
	if err != nil {
		return *new(R), err
	}
	return response, nil
}
