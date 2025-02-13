package policy

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	api "tee-node/api/types"
	"tee-node/internal/utils"
)

var ActiveSigningPolicy *SigningPolicy                                          // Current policy that is being used for signing
var ActiveSigningPolicyHash []byte                                              // The hash of the current policy
var SigningPolicies map[uint32]*SigningPolicy = make(map[uint32]*SigningPolicy) // map of rewardEpochId to policy

// We can use the policy hash as the key for the map, since the hash also contains th rewardEpochId
var ValidVoterWeight map[string]uint16 = make(map[string]uint16)                                           // map of policyHash to the total weight of the valid signatures
var ProcessedPubKeys map[string](map[*ecdsa.PublicKey]bool) = make(map[string](map[*ecdsa.PublicKey]bool)) // map of rewardEpochId to a list of processed public keys

type Signature struct {
	Sig    []byte
	PubKey []byte
}

func DecodeSignPolicyRequest(request *api.PolicySignatureMessage) ([]byte, *ecdsa.PublicKey, error) {
	policySignature := request.Signature
	_pubKey := request.PublicKey

	X, success1 := new(big.Int).SetString(_pubKey.X, 10)
	Y, success2 := new(big.Int).SetString(_pubKey.Y, 10)
	if !success1 || !success2 {
		return nil, nil, fmt.Errorf("failed to decode the public key")
	}

	pubKey := ecdsa.PublicKey{
		X: X,
		Y: Y,
	}
	return policySignature, &pubKey, nil
}

func GetSignerWeight(pubKey *ecdsa.PublicKey, policy *SigningPolicy) uint16 {
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

// Veifies the signature of a voter against the proposed policy
func VerifySigningPolicySignature(activeSigningPolicy *SigningPolicy, proposedPolicyHash []byte, signature []byte, pubKey *ecdsa.PublicKey) bool {
	voterAddress := crypto.PubkeyToAddress(*pubKey)

	// Check if the voter is a signer
	isSigner := false
	for _, addr := range activeSigningPolicy.Voters {
		if addr == voterAddress {
			isSigner = true
			break
		}
	}
	if !isSigner {
		return false
	}
	return utils.VerifySignature(pubKey, proposedPolicyHash, signature)
}

func SignNewSigningPolicy(signingPolicyHash []byte, privKey *ecdsa.PrivateKey) ([]byte, error) {
	if len(signingPolicyHash) != 32 {
		return nil, fmt.Errorf("invalid signing policy hash length")
	}

	hashSignature, err := crypto.Sign(accounts.TextHash(signingPolicyHash), privKey)
	if err != nil {
		return nil, err
	}
	return hashSignature, nil
}

func SigningPolicyHash(signingPolicy []byte) []byte {
	if len(signingPolicy)%32 != 0 {
		signingPolicy = append(signingPolicy, make([]byte, 32-len(signingPolicy)%32)...)
	}
	hash := crypto.Keccak256(signingPolicy[:32], signingPolicy[32:64])
	for i := 2; i < len(signingPolicy)/32; i++ {
		hash = crypto.Keccak256(hash, signingPolicy[i*32:(i+1)*32])
	}
	return hash
}

// CountValidSignatures decodes the policy requests in policySignatureMessages, verifies
// the signature against activeSigningPolicy and counts the weights of valid signatures.
// It returns the policy with the highest weight, the hash of the policy, the total weight
// of the valid signatures, and a map of the public keys that have been used to sign the policy.
func CountValidSignatures(newSigningPolicy *SigningPolicy, policySignatureMessages []*api.PolicySignatureMessage, activeSigningPolicy *SigningPolicy) (uint16, map[*ecdsa.PublicKey]bool, error) {
	newPolicyEncoded, err := EncodeSigningPolicy(newSigningPolicy)
	if err != nil {
		return 0, nil, status.Error(codes.InvalidArgument, "Failed to encode the policy")
	}
	newPolicyHash := SigningPolicyHash(newPolicyEncoded)

	totalWeight := uint16(0)
	messagePubKeys := make(map[*ecdsa.PublicKey]bool)

	for _, policySigReq := range policySignatureMessages {
		signature, pubKey, err := DecodeSignPolicyRequest(policySigReq)
		if err != nil {
			return 0, nil, status.Error(codes.InvalidArgument, "Failed to decode the signature")
		}
		// Check the key is hasn't been used to prevent double signing.
		if _, ok := messagePubKeys[pubKey]; ok {
			return 0, nil, status.Error(codes.InvalidArgument, "Attempted double signing")
		}
		isValid := VerifySigningPolicySignature(activeSigningPolicy, newPolicyHash, signature, pubKey)
		if !isValid {
			return 0, nil, status.Error(codes.InvalidArgument, "Invalid signature")
		} else {
			messagePubKeys[pubKey] = true
		}
		voterWeight := GetSignerWeight(pubKey, activeSigningPolicy)
		if voterWeight == 0 {
			return 0, nil, status.Error(codes.InvalidArgument, "Invalid voter")
		}
		totalWeight += voterWeight
	}
	return totalWeight, messagePubKeys, nil
}

func VerifyPolicyFreshness(sigPolicy *SigningPolicy, currentRewardEpochId uint32, policyHashString string) error {
	// Verify the policy is new and for a valid rewards epoch Id
	if sigPolicy.RewardEpochId != currentRewardEpochId+1 {
		return status.Error(codes.InvalidArgument, "Trying to initialize policy for an invalid reward epoch Id")
	}
	if _, ok := SigningPolicies[sigPolicy.RewardEpochId]; ok {
		// Note: This should be redundant, but just in case
		return status.Error(codes.InvalidArgument, "Policy already exists for the reward epoch")
	}
	return nil
}

// Go through the previous and new signer public keys and check that there are no duplicates
func PreventDoubleSigning(messagePubKeys map[*ecdsa.PublicKey]bool, policyHashString string) error {
	// Check that non of the newly processed public keys have been used before
	if ProcessedPubKeys[policyHashString] == nil {
		// Initialize the map
		ProcessedPubKeys[policyHashString] = messagePubKeys
	} else {

		// First check that none of the public keys have been used before
		for pubKey := range messagePubKeys {
			if _, ok := ProcessedPubKeys[policyHashString][pubKey]; ok {
				return status.Error(codes.InvalidArgument, "Attempted double signing")
			}
		}

		// Only when all the public keys are new, add them to the map
		for pubKey := range messagePubKeys {
			ProcessedPubKeys[policyHashString][pubKey] = true
		}
	}
	return nil
}
