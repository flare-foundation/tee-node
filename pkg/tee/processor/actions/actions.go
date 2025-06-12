package actions

import (
	"github.com/pkg/errors"

	"tee-node/pkg/tee/processor/actions/getactions"
	"tee-node/pkg/tee/processor/actions/policyactions"
	"tee-node/pkg/tee/utils"

	"tee-node/api/types"
)

func ProcessAction(actionData *types.ActionData) ([]byte, error) {
	var err error
	var result []byte
	switch utils.OpHashToString(actionData.OPType) {
	// case "GOVERNANCE":
	// 	result, err = handleGovernanceAction(actionData)
	// case "WALLET":
	// 	result, err = handleWalletAction(actionData)
	case "POLICY":
		result, err = handlePolicyAction(actionData)
	case "GET":
		result, err = handleGetInstruction(actionData)
	default:
		return nil, errors.New("invalid action type")
	}
	if err != nil {
		return nil, err
	}

	return result, nil
}

func handlePolicyAction(actionData *types.ActionData) ([]byte, error) {
	var err error
	response := []byte{}
	switch utils.OpHashToString(actionData.OPCommand) {
	case "INITIALIZE_POLICY":
		err = policyactions.InitializePolicy(actionData.Message)
	case "UPDATE_POLICY":
		err = policyactions.UpdatePolicy(actionData.Message)
	default:
		return nil, errors.New("invalid action type")
	}
	if err != nil {
		return nil, err
	}

	return response, nil
}

// TODO: Implement TEE_INFO and KEY_INFO
func handleGetInstruction(getAction *types.ActionData) ([]byte, error) {
	switch utils.OpHashToString(getAction.OPCommand) {
	case "TEE_INFO":
		return nil, errors.New("TEE_INFO command not implemented yet")

	case "KEY_INFO":
		return nil, errors.New("KEY_INFO command not implemented yet")

	case "TEE_BACKUP":
		return getactions.GetBackupPackage(getAction)

	default:
		return nil, errors.New("unknown OpCommand for WALLET OpType")
	}
}

// func handleGovernanceAction(actionData *api.ActionData, signatures [][]byte) ([]byte, error) {
// 	var err error
// 	switch utils.OpHashToString(actionData.OPCommand) {
// 	case "PAUSE":
// 		var pauseMsg api.PauseTeeMessage
// 		if err := json.Unmarshal(actionData.Message, &pauseMsg); err != nil {
// 			return nil, err
// 		}
// 		err = governanceactions.Pause(pauseMsg, signatures)
// 	case "RESUME":
// 		var resumeMsg api.ResumeTeeMessage
// 		if err := json.Unmarshal(actionData.Message, &resumeMsg); err != nil {
// 			return nil, err
// 		}
// 		err = governanceactions.Resume(resumeMsg, signatures)
// 	case "SET_PAUSING_ADDRESSES":
// 		var setPausingMsg api.PausingAddressSetMessage
// 		if err := json.Unmarshal(actionData.Message, &setPausingMsg); err != nil {
// 			return nil, err
// 		}
// 		err = governanceactions.SetPausingAddresses(setPausingMsg, signatures)
// 	case "UPGRADE_PATH":
// 		var upgradePathMsg api.UpgradePathMessage
// 		if err := json.Unmarshal(actionData.Message, &upgradePathMsg); err != nil {
// 			return nil, err
// 		}
// 		err = governanceactions.NewUpgradePath(upgradePathMsg, signatures)
// 	case "BAN_VERSIONS":
// 		var banVersionsMsg api.BanVersionMessage
// 		if err := json.Unmarshal(actionData.Message, &banVersionsMsg); err != nil {
// 			return nil, err
// 		}
// 		err = governanceactions.BanVersion(banVersionsMsg, signatures)
// 	default:
// 		return nil, errors.New("invalid action type")
// 	}

// 	if err != nil {
// 		return nil, err
// 	}

// 	return []byte{}, nil
// }

// func handleWalletAction(actionData *api.ActionData, signatures [][]byte) ([]byte, error) {
// 	var err error
// 	switch utils.OpHashToString(actionData.OPCommand) {
// 	case "PAUSE":
// 		var pauseMsg api.PauseWalletMessage
// 		if err := json.Unmarshal(actionData.Message, &pauseMsg); err != nil {
// 			return nil, err
// 		}
// 		err = walletactions.Pause(pauseMsg, signatures)
// 	case "RESUME":
// 		var resumeMsg api.ResumeWalletMessage
// 		if err := json.Unmarshal(actionData.Message, &resumeMsg); err != nil {
// 			return nil, err
// 		}
// 		err = walletactions.Resume(resumeMsg, signatures)
// 	case "SET_PAUSING_ADDRESSES":
// 		var setPausingMsg api.PausingAddressSetWalletMessage
// 		if err := json.Unmarshal(actionData.Message, &setPausingMsg); err != nil {
// 			return nil, err
// 		}
// 		err = walletactions.SetPausingAddresses(setPausingMsg, signatures)
// 	default:
// 		return nil, errors.New("invalid action type")
// 	}

// 	if err != nil {
// 		return nil, err
// 	}

// 	return []byte{}, nil
// }
