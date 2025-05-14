package utils

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net/http"

	"tee-node/pkg/config"
	"tee-node/pkg/policy"
	"tee-node/pkg/requests"
	"tee-node/pkg/utils"
	"tee-node/pkg/wallets"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	api "tee-node/api/types"
)

func GenerateRandomValidPolicyAndSigners(epochId uint32, randSeed int64, numVoters int) (*policy.SigningPolicy, []byte, []common.Address, []*ecdsa.PrivateKey, []api.ECDSAPublicKey, error) {
	// Generate random voters and corresponding private keys
	voters, privKeys, pubKeysMap := GenerateRandomVoters(numVoters)

	initialPolicy := GenerateRandomPolicyData(epochId, voters, randSeed)

	initialPolicyBytes, err := policy.EncodeSigningPolicy(&initialPolicy)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	pubKeys := make([]api.ECDSAPublicKey, len(voters))
	for i, voter := range voters {
		pubKeys[i] = api.PubKeyToBytes(pubKeysMap[voter])
	}

	return &initialPolicy, initialPolicyBytes, voters, privKeys, pubKeys, nil
}

func GenerateRandomMultiSignedPolicyArray(epochId uint32, randSeed int64, voters []common.Address, privKeys []*ecdsa.PrivateKey, numPolicies int) ([]api.MultiSignedPolicy, error) {
	// Generate a few more policies and their signatures
	multiSignedPolicyArray := []api.MultiSignedPolicy{}

	_epochId, _randSeed := epochId, randSeed

	for range numPolicies {
		_epochId++
		_randSeed++
		nextPolicy := GenerateRandomPolicyData(_epochId, voters, _randSeed)

		nextPolicyBytes, err := policy.EncodeSigningPolicy(&nextPolicy)
		if err != nil {
			return nil, err
		}

		policySignatures := BuildMultiSignedPolicy(nextPolicyBytes, privKeys)
		multiSignedPolicyArray = append(multiSignedPolicyArray, policySignatures)
	}

	return multiSignedPolicyArray, nil
}

func BuildMultiSignedPolicy(policyBytes []byte, voterPrivKeys []*ecdsa.PrivateKey) api.MultiSignedPolicy {
	PolicySignatureMessages := []*api.SignatureMessage{}

	for _, voterPrivKey := range voterPrivKeys {
		// sig, err := policy.SignNewSigningPolicy(policy.SigningPolicyHash(policyBytes), voterPrivKeys[i])
		sig, err := utils.Sign(policy.SigningPolicyBytesToHash(policyBytes), voterPrivKey)
		if err != nil {
			panic(err)
		}

		PolicySignatureMessages = append(PolicySignatureMessages, &api.SignatureMessage{
			PublicKey: api.PubKeyToBytes(&voterPrivKey.PublicKey),
			Signature: sig,
		})

	}

	return api.MultiSignedPolicy{
		PolicyBytes: policyBytes,
		Signatures:  PolicySignatureMessages,
	}
}

func BuildMockInitializePolicyAction(req *api.InitializePolicyRequest) (*api.SignedAction, error) {
	encoded, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	action := &api.SignedAction{
		Challenge: common.Hash{},
		Data: api.ActionData{
			OPType:    utils.StringToOpHash("POLICY"),
			OPCommand: utils.StringToOpHash("INITIALIZE_POLICY"),
			Message:   encoded,
		},
		Signatures: [][]byte{},
	}
	return action, nil
}

func GenerateRandomVoters(numVoters int) ([]common.Address, []*ecdsa.PrivateKey, map[common.Address]*ecdsa.PublicKey) {
	Voters := make([]common.Address, numVoters)
	privKeys := make([]*ecdsa.PrivateKey, numVoters)
	pubKeys := make(map[common.Address]*ecdsa.PublicKey)

	for i := 0; i < numVoters; i++ {
		voterPrivKey, err := utils.GenerateEthereumPrivateKey()
		if err != nil {
			panic(err)
		}
		voterPubKey := voterPrivKey.PublicKey

		privKeys[i] = voterPrivKey
		Voters[i] = utils.PubkeyToAddress(&voterPubKey)
		pubKeys[Voters[i]] = &voterPubKey
	}

	return Voters, privKeys, pubKeys

}

func GetSignerWeight(pubKey *ecdsa.PublicKey, policy *policy.SigningPolicy) uint16 {
	// Convert the public key to an Ethereum address
	address := crypto.PubkeyToAddress(*pubKey)

	// Find the index of the voter in the policy
	voterIndex := -1
	for i, addr := range policy.Voters {
		if addr == address {
			voterIndex = i
			break
		}
	}
	if voterIndex == -1 {
		return 0
	}
	return policy.Weights[voterIndex]
}

const WEIGHT_DENOMINATION = 1<<16 - 1

func GenerateRandomPolicyData(rewardEpochId uint32, voters []common.Address, seed int64) policy.SigningPolicy {
	// Use specific seed for deterministic results
	rgen := rand.New(rand.NewSource(seed))

	StartVotingRoundId := rgen.Uint32()

	Threshold := uint16((1 << 16) / 2)
	Seed := big.NewInt(rgen.Int63())
	Weights := []uint16{}

	normalizedWeights := RandomNormalizedArray(len(voters), seed)
	for _, w := range normalizedWeights {
		Weights = append(Weights, uint16(w*WEIGHT_DENOMINATION))
	}

	return policy.SigningPolicy{
		RewardEpochId:      rewardEpochId,
		StartVotingRoundId: StartVotingRoundId,
		Threshold:          Threshold,
		Seed:               *Seed,
		Voters:             voters,
		Weights:            Weights,
	}
}

// Loop through the voters and weights and calculate the total weight
// return the index of the voter at which the accumulaterd voterWeight passes the threshold
func GetThresholdReachedVoterIndex(nextPolicy *policy.SigningPolicy, voterPrivKeys []*ecdsa.PrivateKey) (int, uint16) {

	var weightSum uint16 = 0
	for i := 0; i < len(voterPrivKeys); i++ {

		pubKey := voterPrivKeys[i].PublicKey
		voterWeight := GetSignerWeight(&pubKey, nextPolicy)

		weightSum += voterWeight

		if weightSum >= nextPolicy.Threshold {
			return i, weightSum
		}

	}

	return len(voterPrivKeys) - 1, weightSum
}

// RandomNormalizedArray generates an array of n random floats that sum to 1
func RandomNormalizedArray(n int, seed int64) []float64 {
	// Initialize random source with seed
	source := rand.NewSource(seed)
	r := rand.New(source)

	// Generate random numbers
	numbers := make([]float64, n)
	sum := 0.0

	for i := 0; i < n; i++ {
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

// Resets the state of the TEE between tests
func ResetTEEState() {
	policy.DestroyState()
	requests.DestroyState()
	requests.DestroyGarbageCollector()
	requests.ClearRateLimiterState()
	wallets.DestroyState()
	wallets.DestroyGarbageCollector()

	// TODO: Reset any other state that might interfere with the tests
}

// Set the initial policy hash in the config
// We need this to make the tests work for randomly generated policies
func SetMockInitialPolicy(initialPolicyBytes []byte) {
	// Set the initial policy hash in the config
	config.InitialPolicyHash = hex.EncodeToString(policy.SigningPolicyBytesToHash(initialPolicyBytes))
}

// This will construct a Mock Signing Policy, set it on the Tee and return the policy
func GenerateAndSetInitialPolicy(numVoters int, randSeed int64, epochId uint32) (policy.SigningPolicy, []common.Address, []*ecdsa.PrivateKey) {

	// Generate random voters and corresponding private keys
	voters, privKeys, pubKeys := GenerateRandomVoters(numVoters)

	// Generate a random initial policy
	initialPolicy := GenerateRandomPolicyData(epochId, voters, randSeed)

	initialPolicyBytes, _ := policy.EncodeSigningPolicy(&initialPolicy)

	// Set the initial policy hash in the config
	SetMockInitialPolicy(initialPolicyBytes)

	// Set the Active Signing Policy
	policy.SetActiveSigningPolicy(&initialPolicy)
	policy.SetActiveSigningPolicyPublicKeys(pubKeys)

	// Register the validators for the rate limiter
	requests.UpdateRateLimiter(voters)

	return initialPolicy, voters, privKeys
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

// MarshalProviders converts Providers struct to a JSON string.
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

// UnmarshalProviders converts a JSON string back to a Providers struct.
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

func Post[R any](url string, req any) (R, error) {
	requestBody, err := json.Marshal(req)
	if err != nil {
		return *new(R), err
	}
	res, err := http.Post(url, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return *new(R), err
	}
	defer res.Body.Close()
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
