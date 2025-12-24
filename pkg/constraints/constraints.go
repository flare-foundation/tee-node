package constraints

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
)

type sizeConstraint struct {
	originalMessage           int
	additionalFixedMessage    int
	additionalVariableMessage int
}

var defaultConstraint = sizeConstraint{
	originalMessage:           50 * 1024,
	additionalFixedMessage:    100 * 1024,
	additionalVariableMessage: 50 * 1024,
}

var noAdditional = sizeConstraint{
	originalMessage:           50 * 1024,
	additionalFixedMessage:    0,
	additionalVariableMessage: 0,
}

var restore = sizeConstraint{
	originalMessage:           50 * 1024,
	additionalFixedMessage:    100 * 1024,
	additionalVariableMessage: 1024 * 1024,
}

func constraints(opCommand common.Hash) (sizeConstraint, error) {
	oc := op.HashToOPCommand(opCommand)

	switch oc {
	case op.InitializePolicy, op.UpdatePolicy, op.KeyInfo, op.TEEInfo, op.TEEBackup:
		return sizeConstraint{}, errors.New("non instruction opCommand")
	case op.KeyDataProviderRestore, op.KeyDataProviderRestoreTest:
		return restore, nil
	case op.Pay, op.Reissue, op.TEEAttestation, op.KeyGenerate, op.KeyDelete:
		return noAdditional, nil
	case op.Prove:
		return defaultConstraint, nil
	default:
		return defaultConstraint, nil
	}
}

// CheckSize ensures the fixed portion of the instruction adheres to configured
// size limits.
func CheckSize(data *instruction.DataFixed) error {
	c, err := constraints(data.OPCommand)
	if err != nil {
		return err
	}

	switch {
	case len(data.OriginalMessage) > c.originalMessage:
		return errors.New("original message too big")
	case len(data.AdditionalFixedMessage) > c.additionalFixedMessage:
		return errors.New("additional fixed message message too big")
	}

	return nil
}

// CheckSizeVariableMessages enforces size limits on variable messages for the
// given instruction command.
func CheckSizeVariableMessages(opCommand common.Hash, variableMessages []hexutil.Bytes) error {
	c, err := constraints(opCommand)
	if err != nil {
		return err
	}

	for j := range variableMessages {
		if len(variableMessages[j]) > c.additionalVariableMessage {
			return errors.New("additional variable message message too big")
		}
	}

	return nil
}
