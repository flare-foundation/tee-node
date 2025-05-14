package actionservice

import (
	"encoding/hex"
	"encoding/json"

	"strconv"

	"github.com/pkg/errors"

	"tee-node/pkg/attestation"
	"tee-node/pkg/service/actionservice/governanceactions"
	"tee-node/pkg/service/actionservice/policyactions"
	"tee-node/pkg/service/actionservice/walletactions"
	"tee-node/pkg/utils"

	api "tee-node/api/types"
)

func SendAction(action *api.SignedAction) (*api.ActionResponse, error) {
	var err error
	var data []byte
	switch utils.OpHashToString(action.Data.OPType) {
	case "GOVERNANCE":
		data, err = handleGovernanceAction(&action.Data, action.Signatures)
	case "WALLET":
		data, err = handleWalletAction(&action.Data, action.Signatures)
	case "POLICY":
		data, err = handlePolicyAction(&action.Data)
	default:
		return nil, errors.New("invalid action type")
	}

	if err != nil {
		return nil, err
	}

	token, err := attestation.CreateAttestation(
		[]string{
			hex.EncodeToString(action.Challenge[:]),
			strconv.FormatUint(utils.GetTimestampInMilliseconds(), 10),
		},
		attestation.OIDCTokenType,
	) // todo: add response to the attested value?
	if err != nil {
		return nil, err
	}

	return &api.ActionResponse{
		Data:    data,
		Token:   token,
		Success: true,
	}, nil
}

func handleGovernanceAction(actionData *api.ActionData, signatures [][]byte) ([]byte, error) {
	var err error
	switch utils.OpHashToString(actionData.OPCommand) {
	case "PAUSE":
		var pauseMsg api.PauseTeeMessage
		if err := json.Unmarshal(actionData.Message, &pauseMsg); err != nil {
			return nil, err
		}
		err = governanceactions.Pause(pauseMsg, signatures)
	case "RESUME":
		var resumeMsg api.ResumeTeeMessage
		if err := json.Unmarshal(actionData.Message, &resumeMsg); err != nil {
			return nil, err
		}
		err = governanceactions.Resume(resumeMsg, signatures)
	case "SET_PAUSING_ADDRESSES":
		var setPausingMsg api.PausingAddressSetMessage
		if err := json.Unmarshal(actionData.Message, &setPausingMsg); err != nil {
			return nil, err
		}
		err = governanceactions.SetPausingAddresses(setPausingMsg, signatures)
	case "UPGRADE_PATH":
		var upgradePathMsg api.UpgradePathMessage
		if err := json.Unmarshal(actionData.Message, &upgradePathMsg); err != nil {
			return nil, err
		}
		err = governanceactions.NewUpgradePath(upgradePathMsg, signatures)
	case "BAN_VERSIONS":
		var banVersionsMsg api.BanVersionMessage
		if err := json.Unmarshal(actionData.Message, &banVersionsMsg); err != nil {
			return nil, err
		}
		err = governanceactions.BanVersion(banVersionsMsg, signatures)
	default:
		return nil, errors.New("invalid action type")
	}

	if err != nil {
		return nil, err
	}

	return []byte{}, nil
}

func handleWalletAction(actionData *api.ActionData, signatures [][]byte) ([]byte, error) {
	var err error
	switch utils.OpHashToString(actionData.OPCommand) {
	case "PAUSE":
		var pauseMsg api.PauseWalletMessage
		if err := json.Unmarshal(actionData.Message, &pauseMsg); err != nil {
			return nil, err
		}
		err = walletactions.Pause(pauseMsg, signatures)
	case "RESUME":
		var resumeMsg api.ResumeWalletMessage
		if err := json.Unmarshal(actionData.Message, &resumeMsg); err != nil {
			return nil, err
		}
		err = walletactions.Resume(resumeMsg, signatures)
	case "SET_PAUSING_ADDRESSES":
		var setPausingMsg api.PausingAddressSetWalletMessage
		if err := json.Unmarshal(actionData.Message, &setPausingMsg); err != nil {
			return nil, err
		}
		err = walletactions.SetPausingAddresses(setPausingMsg, signatures)
	default:
		return nil, errors.New("invalid action type")
	}

	if err != nil {
		return nil, err
	}

	return []byte{}, nil
}

func handlePolicyAction(actionData *api.ActionData) ([]byte, error) {
	var err error
	response := []byte{}
	switch utils.OpHashToString(actionData.OPCommand) {
	case "INITIALIZE_POLICY":
		err = policyactions.InitializePolicy(actionData.Message)
	default:
		return nil, errors.New("invalid action type")
	}

	if err != nil {
		return nil, err
	}

	return response, nil
}
