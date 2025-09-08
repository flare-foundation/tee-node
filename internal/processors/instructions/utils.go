package instructions

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
)

func checkInstructionData(data *instruction.DataFixed) error {
	if data == nil {
		return errors.New("instruction data is nil")
	}

	valid := op.IsValidPair(data.OPType, data.OPCommand)
	if !valid {
		return errors.New("invalid OPType, OPCommand pair")
	}

	return nil
}

func voteHash(instructionDataFixed *instruction.DataFixed, signatures, variableMessages []hexutil.Bytes, signers []common.Address, timestamps []uint64) (common.Hash, error) {
	if len(signatures) != len(timestamps) {
		return common.Hash{}, errors.New("number of signatures and timestamps do not match")
	}
	if len(signers) != len(timestamps) {
		return common.Hash{}, errors.New("number of signers and timestamps do not match")
	}
	if len(variableMessages) != len(timestamps) {
		return common.Hash{}, errors.New("number of variableMessages and timestamps do not match")
	}

	// check that timestamps are increasing
	for j := range len(timestamps) - 1 {
		if timestamps[j] > timestamps[j+1] {
			return common.Hash{}, errors.New("timestamps are not increasing")
		}
	}

	voteHash, err := instructionDataFixed.InitialVoteHash()
	if err != nil {
		return common.Hash{}, err
	}

	for i := range len(signatures) {
		voteHash, err = instruction.NextVoteHash(voteHash, uint64(i), signatures[i], variableMessages[i], timestamps[i])
		if err != nil {
			return common.Hash{}, err
		}
	}

	return voteHash, nil
}

func checkPolicyValidity(policyID, activePolicyID uint32) error {
	if activePolicyID-policyID > 1 {
		return errors.New("signing policy too old")
	}
	return nil
}
