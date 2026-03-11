package instructions

import (
	"encoding/json"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	cpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/constraints"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/policy"
	"github.com/flare-foundation/tee-node/pkg/processorutils"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
)

type ProcessorFunction func(submissionTag types.SubmissionTag, dataFixed *instruction.DataFixed, variableMessages []hexutil.Bytes, signers []common.Address, signingPolicy *cpolicy.SigningPolicy) (data []byte, additionalResultStatus []byte, err error)

type Processor struct {
	f               ProcessorFunction
	iSAndD          node.IdentifierSignerAndDecrypter
	pStorage        *policy.Storage
	immediateResult bool
}

// NewProcessor builds a Processor that wraps the provided instruction handler
// with common preprocessing and validation logic.
func NewProcessor(f ProcessorFunction, iSAndD node.IdentifierSignerAndDecrypter, pStorage *policy.Storage, immediateResult bool) Processor {
	return Processor{
		f:               f,
		iSAndD:          iSAndD,
		pStorage:        pStorage,
		immediateResult: immediateResult,
	}
}

// Process validates an instruction action and routes it through the configured
// instruction handler, packaging the result for the router.
func (p Processor) Process(a *types.Action) types.ActionResult {
	data, err := processorutils.Parse[instruction.DataFixed](a.Data.Message)
	if err != nil {
		return processorutils.Invalid(a, err)
	}

	signers, signingPolicy, err := preprocess(a, data, p.pStorage, p.iSAndD.TeeID())
	if err != nil {
		return processorutils.Invalid(a, err)
	}

	pMessage, additionalStatus, err := p.f(a.Data.SubmissionTag, data, a.AdditionalVariableMessages, signers, signingPolicy)
	if err != nil {
		return processorutils.Invalid(a, err)
	}

	var message []byte
	var status uint8

	switch a.Data.SubmissionTag {
	case types.Threshold:
		message = pMessage
		if p.immediateResult {
			status = 1
		} else {
			status = 2
		}

	case types.End:
		msg, err := rewardingData(data, a.Signatures, a.AdditionalVariableMessages, signers, a.Timestamps, additionalStatus, p.iSAndD)
		if err != nil {
			return processorutils.Invalid(a, err)
		}
		message = msg
		status = 1

	default:
		return processorutils.Invalid(a, errors.New("invalid submissionTag"))
	}

	result := types.ActionResult{
		ID:            a.Data.ID,
		SubmissionTag: a.Data.SubmissionTag,
		Status:        status,
		Version:       settings.EncodingVersion,
	}

	result.AdditionalResultStatus = additionalStatus
	result.OPCommand = data.OPCommand
	result.OPType = data.OPType
	result.Data = message

	return result
}

func preprocess(a *types.Action, data *instruction.DataFixed, pStorage *policy.Storage, teeId common.Address) ([]common.Address, *cpolicy.SigningPolicy, error) {
	pStorage.RLock()
	signingPolicy, err := pStorage.SigningPolicy(data.RewardEpochID)
	if err != nil {
		pStorage.RUnlock()
		return nil, nil, err
	}

	activePolicy, err := pStorage.ActiveSigningPolicy()
	pStorage.RUnlock()
	if err != nil {
		return nil, nil, err
	}

	err = checkPolicyValidity(signingPolicy.RewardEpochID, activePolicy.RewardEpochID)
	if err != nil {
		return nil, nil, err
	}

	err = validateInstructionData(data, a.AdditionalVariableMessages, teeId, a.Data.ID)
	if err != nil {
		return nil, nil, err
	}

	signers, err := signaturesToSigners(data, a.AdditionalVariableMessages, a.Signatures)
	if err != nil {
		return nil, nil, err
	}

	err = processorutils.CheckThresholds(data, signers, signingPolicy)
	if err != nil {
		return nil, nil, err
	}

	return signers, signingPolicy, nil
}

// validateInstructionData validates the instruction data and counts the votes.
func validateInstructionData(data *instruction.DataFixed, additionalVariableMessages []hexutil.Bytes, expectedTeeID common.Address, actionID common.Hash) error {
	if data.TeeID != expectedTeeID {
		return errors.New("unexpected tee ID")
	}
	if data.InstructionID != actionID {
		return errors.New("action ID and instruction ID do not match")
	}

	err := checkInstructionData(data)
	if err != nil {
		return err
	}

	err = constraints.CheckSize(data)
	if err != nil {
		return err
	}

	err = constraints.CheckSizeVariableMessages(data.OPCommand, additionalVariableMessages)
	if err != nil {
		return err
	}

	return nil
}

func signaturesToSigners(instructionDataFixed *instruction.DataFixed, variableMessages, signatures []hexutil.Bytes) ([]common.Address, error) {
	if len(variableMessages) != len(signatures) {
		return nil, errors.New("the number of variable messages does not match the number of signatures")
	}

	signers := make([]common.Address, len(signatures))
	signersCheck := make(map[common.Address]bool)
	for i, signature := range signatures {
		instructionData := instruction.Data{DataFixed: *instructionDataFixed}
		instructionData.AdditionalVariableMessage = variableMessages[i]

		hash, err := instructionData.HashForSigning()
		if err != nil {
			return nil, err
		}
		signer, err := utils.SignatureToSignersAddress(hash[:], signature)
		if err != nil {
			return nil, err
		}
		if _, ok := signersCheck[signer]; ok {
			return nil, errors.New("double signing")
		}

		signers[i] = signer
		signersCheck[signer] = true
	}

	return signers, nil
}

func rewardingData(id *instruction.DataFixed, signatures, variableMessages []hexutil.Bytes, signers []common.Address, timestamps []uint64, status hexutil.Bytes, signer node.Signer) ([]byte, error) {
	iHash, err := id.HashFixed()
	if err != nil {
		return nil, err
	}

	voteHash, err := voteHash(id, signatures, variableMessages, signers, timestamps)
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(voteHash[:])
	if err != nil {
		return nil, errors.New("could not sign vote hash")
	}

	variableMessageHashes := make([]common.Hash, len(variableMessages))
	for j, msg := range variableMessages {
		variableMessageHashes[j] = crypto.Keccak256Hash(msg)
	}

	rd := types.RewardingData{
		VoteSequence: types.VoteSequence{
			VoteHash:                        voteHash,
			InstructionID:                   id.InstructionID,
			InstructionHash:                 iHash,
			RewardEpochID:                   id.RewardEpochID,
			TeeID:                           id.TeeID,
			Signatures:                      signatures,
			AdditionalVariableMessageHashes: variableMessageHashes,
			Timestamps:                      timestamps,
		},
		AdditionalData: status,
		Version:        settings.EncodingVersion,
		Signature:      signature,
	}

	jsonRD, err := json.Marshal(rd)
	if err != nil {
		return nil, err
	}

	return jsonRD, nil
}
