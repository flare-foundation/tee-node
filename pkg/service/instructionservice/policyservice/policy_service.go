package policyservice

// todo: maybe rename to policyinstruction ?
import (
	"encoding/json"
	api "tee-node/api/types"
	"tee-node/pkg/policy"

	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
)

func UpdatePolicy(instructionData *instruction.DataFixed) error {
	// multiSignedPolicy doesn't get encoded in the originalMessage. The entire struct is
	//  in the AdditionalFixedMessage
	var multiSignedPolicy api.MultiSignedPolicy
	err := json.Unmarshal(instructionData.AdditionalFixedMessage, &multiSignedPolicy)

	if err != nil {
		return err
	}

	err = policy.UpdatePolicyRequest(multiSignedPolicy)
	if err != nil {
		return err
	}

	return nil
}
