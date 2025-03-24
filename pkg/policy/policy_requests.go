package policy

import (
	"encoding/hex"
	api "tee-node/api/types"
	"tee-node/pkg/config"
	"tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func InitializePolicyRequest(InitialPolicyBytes []byte, NewPolicyRequests []api.MultiSignedPolicy) error {
	if ActiveSigningPolicy != nil {
		return status.Error(codes.InvalidArgument, "policy already initialized")
	}

	// Initialize the original signing policy and store it in the map
	currentPolicy, err := DecodeSigningPolicy(InitialPolicyBytes)
	if err != nil {
		return status.Error(codes.InvalidArgument, "failed to decode the initial policy")
	}
	currentPolicyHash := SigningPolicyHash(InitialPolicyBytes)

	// Check that the policy matches the initial policy in the config file
	if config.InitialPolicyHash != hex.EncodeToString(currentPolicyHash) {
		return status.Error(codes.InvalidArgument, "policy does not match the initial policy in the config file")
	} else {
		SetSigningPolicy(currentPolicy, currentPolicyHash)
	}

	// Go through the policies for each reward epoch and update the current policy
	for _, policyRequest := range NewPolicyRequests {
		err = UpdatePolicyRequest(policyRequest)
		if err != nil {
			return err
		}
	}

	return nil
}

func UpdatePolicyRequest(policyRequest api.MultiSignedPolicy) error {
	sigPolicy, err := DecodeSigningPolicy(policyRequest.PolicyBytes)
	if err != nil {
		return status.Error(codes.InvalidArgument, "failed to decode the policy")
	}

	if sigPolicy.RewardEpochId != ActiveSigningPolicy.RewardEpochId+1 {
		return errors.New("policy is not active")
	}

	signers := make(map[common.Address][]byte)
	for _, sig := range policyRequest.Signatures {
		providerAddress, err := utils.CheckSignature(SigningPolicyHash(policyRequest.PolicyBytes), sig.Signature, ActiveSigningPolicy.Voters)
		if err != nil {
			return err
		}
		signers[providerAddress] = sig.Signature
	}

	if WeightOfSigners(signers, ActiveSigningPolicy) >= ActiveSigningPolicy.Threshold {
		policyHash := SigningPolicyHash(policyRequest.PolicyBytes)
		SetSigningPolicy(sigPolicy, policyHash)
	} else {
		return errors.New("threshold not reached")
	}

	return nil
}
