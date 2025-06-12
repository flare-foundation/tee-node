package policyactions

import (
	"encoding/json"
	"tee-node/pkg/tee/policy"

	"tee-node/api/types"
)

func InitializePolicy(message []byte) error {
	var req types.InitializePolicyRequest
	err := json.Unmarshal(message, &req)
	if err != nil {
		return err
	}

	err = policy.InitializePolicyRequest(req.InitialPolicyBytes, req.Policies, req.LatestPolicyPublicKeys)
	if err != nil {
		return err
	}

	return nil
}

func UpdatePolicy(message []byte) error {
	var updatePolicyRequest types.UpdatePolicyRequest
	err := json.Unmarshal(message, &updatePolicyRequest)
	if err != nil {
		return err
	}

	err = policy.UpdatePolicyRequest(updatePolicyRequest.NewPolicy, updatePolicyRequest.LatestPolicyPublicKeys)
	if err != nil {
		return err
	}

	return nil
}
