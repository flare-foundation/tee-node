package direct

import (
	"github.com/pkg/errors"

	"github.com/flare-foundation/tee-node/internal/processor/direct/getutils"
	"github.com/flare-foundation/tee-node/internal/processor/direct/policyutils"
	"github.com/flare-foundation/tee-node/pkg/op"
	"github.com/flare-foundation/tee-node/pkg/types"
)

func ProcessDirectInstruction(i *types.DirectInstruction) ([]byte, error) {
	var err error
	var result []byte
	switch op.HashToOPType(i.OPType) {
	case op.Policy:
		result, err = executePolicyDirectInstruction(i)
	case op.Get:
		result, err = getData(i)
	default:
		return nil, errors.New("invalid action type")
	}
	if err != nil {
		return nil, err
	}

	return result, nil
}

func executePolicyDirectInstruction(i *types.DirectInstruction) ([]byte, error) {
	var err error
	response := []byte{}

	switch op.HashToOPCommand(i.OPCommand) {
	case op.InitializePolicy:
		err = policyutils.InitializePolicy(i.Message)
	case op.UpdatePolicy:
		err = policyutils.UpdatePolicy(i.Message)
	default:
		return nil, errors.New("invalid action type")
	}
	if err != nil {
		return nil, err
	}

	return response, nil
}

func getData(i *types.DirectInstruction) ([]byte, error) {
	switch op.HashToOPCommand(i.OPCommand) {
	case op.TEEInfo:
		return getutils.GetTeeInfo(i)

	case op.KeyInfo:
		return getutils.GetKeyInfoPackage()

	case op.TEEBackup:
		return getutils.GetBackupPackage(i)

	default:
		return nil, errors.New("unknown OpCommand for WALLET OpType")
	}
}
