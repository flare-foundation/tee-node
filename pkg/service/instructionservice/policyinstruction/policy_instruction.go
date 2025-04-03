package policyinstruction

// todo: maybe rename to policyinstruction ?
import (
	"encoding/json"
	api "tee-node/api/types"
	"tee-node/pkg/policy"
	"tee-node/pkg/requests"

	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
)

func UpdatePolicy(instructionData *instruction.DataFixed) error {
	// multiSignedPolicy doesn't get encoded in the originalMessage. The entire struct is
	//  in the AdditionalFixedMessage
	var updatePolicyRequest api.UpdatePolicyAdditionalFixedMessage
	err := json.Unmarshal(instructionData.AdditionalFixedMessage, &updatePolicyRequest)
	if err != nil {
		return err
	}

	err = policy.UpdatePolicyRequest(updatePolicyRequest.NewPolicyRequest, updatePolicyRequest.LatestPolicyPublicKeys)
	if err != nil {
		return err
	}

	requests.UpdateRateLimiter(policy.GetActiveSigningPolicy().Voters)

	return nil
}
