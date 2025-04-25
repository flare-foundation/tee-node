package policyinstruction

// todo: maybe rename to policyinstruction ?
import (
	"encoding/json"
	api "tee-node/api/types"
	"tee-node/pkg/config"
	"tee-node/pkg/policy"
	"tee-node/pkg/requests"
	"tee-node/pkg/wallets"

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

	newPolicy, pubKeysMap, err := policy.UpdatePolicyRequest(updatePolicyRequest.NewPolicyRequest, updatePolicyRequest.LatestPolicyPublicKeys)
	if err != nil {
		return err
	}
	newPolicyPublicKeys, err := policy.GetSigningPolicyPublicKeys(newPolicy, pubKeysMap)
	if err != nil {
		return err
	}
	normalizedWeights := config.WeightsNormalization(newPolicy.Weights)

	newBackupWalletsStorage, err := wallets.NewBackupWalletsStorageWithNewPolicy(newPolicyPublicKeys, config.DataProvidersBackupThreshold, normalizedWeights, newPolicy.RewardEpochId)
	if err != nil {
		return err
	}

	policy.SetActiveSigningPolicyAndPubKeys(newPolicy, pubKeysMap)
	wallets.UpdateBackupStorage(newBackupWalletsStorage)

	requests.UpdateRateLimiter(policy.GetActiveSigningPolicy().Voters)

	return nil
}
