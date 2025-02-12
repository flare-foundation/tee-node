package utils

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"log"
	"math/big"
	"math/rand"
	"time"

	"tee-node/internal/policy"
	"tee-node/internal/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	api "tee-node/api/types"
)

func GenerateRandomValidPolicyAndSigners(epochId uint32, randSeed int64, numVoters int) (*policy.SigningPolicy, []byte, []common.Address, []*ecdsa.PrivateKey, error) {
	// Generate random voters and corresponding private keys
	voters, privKeys := GenerateRandomVoters(numVoters)

	initialPolicy := GenerateRandomPolicyData(epochId, voters, randSeed)

	initialPolicyBytes, err := policy.EncodeSigningPolicy(&initialPolicy)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return &initialPolicy, initialPolicyBytes, voters, privKeys, nil
}

func GenerateRandomSignNewPolicyRequestArrays(epochId uint32, randSeed int64, voters []common.Address, privKeys []*ecdsa.PrivateKey, numPolicies int) ([]*api.SignNewPolicyRequest, error) {
	// Generate a few more policies and their signatures
	policySignaturesArray := []*api.SignNewPolicyRequest{}

	_epochId, _randSeed := epochId, randSeed

	for i := 0; i < numPolicies; i++ {

		_epochId++
		_randSeed++
		nextPolicy := GenerateRandomPolicyData(_epochId, voters, _randSeed)

		nextPolicyBytes, err := policy.EncodeSigningPolicy(&nextPolicy)
		if err != nil {
			return nil, err
		}

		policySignatures := BuildPolicySignature(nextPolicyBytes, privKeys)
		policySignaturesArray = append(policySignaturesArray, policySignatures)
	}

	return policySignaturesArray, nil
}

func BuildPolicySignature(policyBytes []byte, voterPrivKeys []*ecdsa.PrivateKey) *api.SignNewPolicyRequest {
	PolicySignatureMessages := []*api.PolicySignatureMessage{}

	for i, voterPrivKey := range voterPrivKeys {

		voterPubKey := voterPrivKey.PublicKey

		sig, err := policy.SignNewSigningPolicy(policy.SigningPolicyHash(policyBytes), voterPrivKeys[i])
		if err != nil {
			panic(err)
		}

		PolicySignatureMessages = append(PolicySignatureMessages, &api.PolicySignatureMessage{
			PublicKey: &api.ECDSAPublicKey{
				X: voterPubKey.X.String(),
				Y: voterPubKey.Y.String(),
			},
			Signature: sig,
		})

	}

	return &api.SignNewPolicyRequest{
		PolicyBytes:             policyBytes,
		PolicySignatureMessages: PolicySignatureMessages,
	}
}

// Always returns the same voters and private keys
func GenerateRandomVoters(numVoters int) ([]common.Address, []*ecdsa.PrivateKey) {
	Voters := make([]common.Address, numVoters)
	privKeys := make([]*ecdsa.PrivateKey, numVoters)

	for i := 0; i < numVoters; i++ {
		voterPrivKey, err := utils.GenerateEthereumPrivateKey()
		if err != nil {
			panic(err)
		}
		voterPubKey := voterPrivKey.PublicKey

		privKeys[i] = voterPrivKey
		Voters[i] = utils.PubkeyToAddress(&voterPubKey)
	}

	return Voters, privKeys

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
func ResetSigningServiceState() {
	policy.ActiveSigningPolicy = nil
	policy.ActiveSigningPolicyHash = nil
	policy.SigningPolicies = make(map[uint32]*policy.SigningPolicy)

	policy.ValidVoterWeight = make(map[string]uint16)
	policy.ProcessedPubKeys = make(map[string](map[*ecdsa.PublicKey]bool))

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

func NewGRPCClient(target string) (*grpc.ClientConn, error) {
	// Create slice for dial options
	var opts []grpc.DialOption

	// 1. Basic options
	opts = append(opts,
		grpc.WithTransportCredentials(insecure.NewCredentials()), // Only for development
		grpc.WithIdleTimeout(60*time.Second),                     // Idle timeout (close connection if idle)
		grpc.WithUnaryInterceptor(ClientLoggingInterceptor),      // Log requests
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                10 * time.Second, // send pings every 10 seconds if there is no activity
			Timeout:             5 * time.Second,  // wait 5 seconds for ping response
			PermitWithoutStream: true,             // allow pings even without active streams
		}),
		grpc.WithDefaultServiceConfig(`{  
            "methodConfig": [{  
                 "name": [  
                {"service": "signing.SigningService"},  
                {"service": "attestation.AttestationService"}  
            ],  
                "waitForReady": true,  
                "retryPolicy": {  
                    "MaxAttempts": 3,  
                    "InitialBackoff": "0.1s",  
                    "MaxBackoff": "1s",  
                    "BackoffMultiplier": 2.0,  
                    "RetryableStatusCodes": ["UNAVAILABLE"]  
                }  
            }]  
        }`), // Retry policy
	)

	// Connect to the server
	return grpc.NewClient(target, opts...)
}

// ClientLoggingInterceptor logs client requests
func ClientLoggingInterceptor(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	start := time.Now()
	err := invoker(ctx, method, req, reply, cc, opts...)
	log.Printf("method: %s, duration: %v, error: %v", method, time.Since(start), err)
	return err
}
