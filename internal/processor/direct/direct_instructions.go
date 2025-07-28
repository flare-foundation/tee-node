package direct

import (
	"github.com/pkg/errors"

	"github.com/flare-foundation/tee-node/internal/processor/direct/getutils"
	"github.com/flare-foundation/tee-node/internal/processor/direct/policyutils"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
)

func ProcessDirectInstruction(instruction *types.DirectInstruction) ([]byte, error) {
	var err error
	var result []byte
	switch utils.OpHashToString(instruction.OPType) {
	case "POLICY":
		result, err = executePolicyDirectInstruction(instruction)
	case "GET":
		result, err = getData(instruction)
	default:
		return nil, errors.New("invalid action type")
	}
	if err != nil {
		return nil, err
	}

	return result, nil
}

func executePolicyDirectInstruction(instruction *types.DirectInstruction) ([]byte, error) {
	var err error
	response := []byte{}
	switch utils.OpHashToString(instruction.OPCommand) {
	case "INITIALIZE_POLICY":
		err = policyutils.InitializePolicy(instruction.Message)
	case "UPDATE_POLICY":
		err = policyutils.UpdatePolicy(instruction.Message)
	default:
		return nil, errors.New("invalid action type")
	}
	if err != nil {
		return nil, err
	}

	return response, nil
}

func getData(instruction *types.DirectInstruction) ([]byte, error) {
	switch utils.OpHashToString(instruction.OPCommand) {
	case "TEE_INFO":
		return getutils.GetTeeInfo(instruction)

	case "KEY_INFO":
		return getutils.GetKeyInfoPackage()

	case "TEE_BACKUP":
		return getutils.GetBackupPackage(instruction)

	default:
		return nil, errors.New("unknown OpCommand for WALLET OpType")
	}
}
