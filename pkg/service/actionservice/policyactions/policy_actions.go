package policyactions

import (
	"encoding/json"
	"tee-node/pkg/policy"
	"tee-node/pkg/requests"

	api "tee-node/api/types"
)

func InitializePolicy(message []byte) error {
	var req *api.InitializePolicyRequest
	err := json.Unmarshal(message, &req)
	if err != nil {
		return err
	}

	err = policy.InitializePolicyRequest(req.InitialPolicyBytes, req.NewPolicyRequests, req.LatestPolicyPublicKeys)
	if err != nil {
		return err
	}

	// Register the validators from the latest policy for the ratelimiter
	requests.UpdateRateLimiter(policy.GetActiveSigningPolicy().Voters)

	return nil
}
