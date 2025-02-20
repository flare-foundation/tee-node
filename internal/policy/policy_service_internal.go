package policy

import (
	api "tee-node/api/types"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func InitializePolicyInternal(req *api.InitializePolicyRequest) error {
	if ActiveSigningPolicy != nil {
		return status.Error(codes.InvalidArgument, "policy already initialized")
	}

	// Initialize the original signing policy and store it in the map
	currentPolicy, err := DecodeSigningPolicy(req.InitialPolicyBytes)
	if err != nil {
		return status.Error(codes.InvalidArgument, "failed to decode the initial policy")
	}
	currentPolicyHash := SigningPolicyHash(req.InitialPolicyBytes)
	SigningPolicies[currentPolicy.RewardEpochId] = currentPolicy

	// Go through the policies for each reward epoch and update the current policy
	for _, policyRequest := range req.NewPolicyRequests {
		sigPolicy, err := DecodeSigningPolicy(policyRequest.PolicyBytes)
		if err != nil {
			return status.Error(codes.InvalidArgument, "failed to decode the policy")
		}
		policyHash := SigningPolicyHash(policyRequest.PolicyBytes)

		validVoterWeight, messagePubKeys, err := CountValidSignatures(sigPolicy, policyRequest.PolicySignatureMessages, currentPolicy)
		if err != nil {
			return err
		}

		err = VerifyPolicyFreshness(sigPolicy, currentPolicy.RewardEpochId, EncodeToHex(policyHash))
		if err != nil {
			return err
		}

		err = PreventDoubleSigning(messagePubKeys, EncodeToHex(policyHash))
		if err != nil {
			return err
		}

		// Check if the number of valid signatures is less than the threshold
		if validVoterWeight < sigPolicy.Threshold {
			return status.Error(codes.InvalidArgument, "Not enough valid signatures")
		}

		// Update the current policy and policy hash
		currentPolicy = sigPolicy
		currentPolicyHash = policyHash

		// Store the policy in the map
		SigningPolicies[sigPolicy.RewardEpochId] = sigPolicy
	}

	// Set the active policy and policy hash (This is the latest policy, that will be used for signing)
	ActiveSigningPolicy = currentPolicy
	ActiveSigningPolicyHash = currentPolicyHash

	return nil
}

func SignNewPolicyInternal(req *api.SignNewPolicyRequest) error {
	proposedPolicy, err := DecodeSigningPolicy(req.PolicyBytes)
	if err != nil {
		return status.Error(codes.InvalidArgument, "failed to decode the policy")
	}
	proposedPolicyHash := SigningPolicyHash(req.PolicyBytes)

	msgVoterWeight, messagePubKeys, err := CountValidSignatures(proposedPolicy, req.PolicySignatureMessages, ActiveSigningPolicy)
	if err != nil {
		return err
	}

	// Get the rewardEpochId from the proposed policy
	err = VerifyPolicyFreshness(proposedPolicy, ActiveSigningPolicy.RewardEpochId, EncodeToHex(proposedPolicyHash))
	if err != nil {
		return err
	}

	policyHashString := EncodeToHex(proposedPolicyHash)
	err = PreventDoubleSigning(messagePubKeys, policyHashString)
	if err != nil {
		return err
	}

	// Check if the policy for that epochId is already registered
	if _, ok := SigningPolicies[proposedPolicy.RewardEpochId]; ok {
		return status.Error(codes.InvalidArgument, "policy already exists for the reward epoch")
	}

	// Update the valid voter weight
	ValidVoterWeight[policyHashString] += msgVoterWeight

	// If the weight is greater than the threshold, update the active policy
	if ValidVoterWeight[policyHashString] >= ActiveSigningPolicy.Threshold {
		ActiveSigningPolicy = proposedPolicy
		ActiveSigningPolicyHash = proposedPolicyHash
		SigningPolicies[proposedPolicy.RewardEpochId] = proposedPolicy

	}

	return nil

}
