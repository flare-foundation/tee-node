package policy

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	api "tee-node/api/types"
)

var ActiveSigningPolicy *SigningPolicy        // Current policy that is being used for signing
var ActiveSigningPolicyHash []byte            // The hash of the current policy
var signingPolicies map[uint32]*SigningPolicy // map of rewardEpochId to policy

func init() {
	signingPolicies = make(map[uint32]*SigningPolicy)
}

func SetNewPolicyInternal(req *api.SignNewPolicyRequest) error {
	proposedPolicy, err := DecodeSigningPolicy(req.PolicyBytes)
	if err != nil {
		return status.Error(codes.InvalidArgument, "failed to decode the policy")
	}
	proposedPolicyHash := SigningPolicyHash(req.PolicyBytes)

	// Get the rewardEpochId from the proposed policy
	err = VerifyPolicyFreshness(proposedPolicy, ActiveSigningPolicy.RewardEpochId)
	if err != nil {
		return err
	}

	SetSigningPolicy(proposedPolicy, proposedPolicyHash)

	return nil
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

func WeightOfSigners(signers map[common.Address][]byte, signingPolicy *SigningPolicy) uint16 {
	currentWeight := uint16(0)
	for i, voter := range signingPolicy.Voters {
		if _, ok := signers[voter]; ok {
			currentWeight += signingPolicy.Weights[i]
		}
	}

	return currentWeight
}

func VerifyPolicyFreshness(sigPolicy *SigningPolicy, currentRewardEpochId uint32) error {
	// Verify the policy is new and for a valid rewards epoch Id
	if sigPolicy.RewardEpochId <= currentRewardEpochId {
		return status.Error(codes.InvalidArgument, "Trying to initialize policy for an invalid reward epoch Id")
	}
	if _, ok := signingPolicies[sigPolicy.RewardEpochId]; ok {
		return status.Error(codes.InvalidArgument, "Policy already exists for the reward epoch")
	}

	return nil
}

// todo: policyHash should be obtained from policy
func SetSigningPolicy(policy *SigningPolicy, policyHash []byte) {
	ActiveSigningPolicy = policy
	ActiveSigningPolicyHash = policyHash
	signingPolicies[policy.RewardEpochId] = policy
}

// todo mutex
func GetSigningPolicy(epochId uint32) *SigningPolicy {
	return signingPolicies[epochId]
}

// Note: This is useful for tests, but it would also be useful for upgrades, where a TEE get's shutdown.
func DestoryState() {
	ActiveSigningPolicy = nil
	ActiveSigningPolicyHash = nil
	signingPolicies = make(map[uint32]*SigningPolicy)

}
