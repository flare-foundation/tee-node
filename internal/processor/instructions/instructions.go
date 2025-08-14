package instructions

import (
	"encoding/json"

	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/policy"
	"github.com/flare-foundation/tee-node/internal/processor/instructions/ftdcutils"
	"github.com/flare-foundation/tee-node/internal/processor/instructions/regutils"
	"github.com/flare-foundation/tee-node/internal/processor/instructions/signutils"
	"github.com/flare-foundation/tee-node/internal/processor/instructions/walletutils"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/types"

	commonpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/pkg/errors"
)

func ProcessInstruction(
	instructionData *instruction.DataFixed,
	variableMessages, signatures []hexutil.Bytes,
	submissionTag types.SubmissionTag,
	timestamps []uint64,
) ([]byte, []byte, error) {
	signingPolicy, err := checkInstructionData(instructionData)
	if err != nil {
		return nil, nil, err
	}

	err = validateInstructionDataSize(instructionData)
	if err != nil {
		return nil, nil, err
	}

	signers, err := signaturesToSigners(instructionData, variableMessages, signatures)
	if err != nil {
		return nil, nil, err
	}

	thresholdReached, dataProviderIndex, err := checkDataProvidersThreshold(instructionData, signers, signingPolicy)
	if err != nil {
		return nil, nil, err
	}
	if !thresholdReached {
		return nil, nil, errors.New("threshold not reached")
	}

	executionResult, resultStatus, err := validateOrExecuteInstruction(instructionData, variableMessages, signers, dataProviderIndex, submissionTag, signingPolicy.RawBytes())
	if err != nil {
		return nil, resultStatus, err
	}

	var result []byte
	switch submissionTag {
	case types.Threshold:
		result = executionResult

	case types.End:
		instructionHash, err := instructionData.HashFixed()
		if err != nil {
			return nil, nil, err
		}

		voteHash, err := voteHash(instructionData, signatures, variableMessages, signers, timestamps)
		if err != nil {
			return nil, nil, err
		}
		signature, err := node.Sign(voteHash[:])
		if err != nil {
			return nil, nil, err
		}

		voteSequence := types.RewardingData{
			VoteSequence: types.VoteSequence{
				VoteHash:                   voteHash,
				InstructionId:              instructionData.InstructionID,
				InstructionHash:            instructionHash,
				RewardEpochId:              instructionData.RewardEpochID,
				TeeId:                      instructionData.TeeID,
				Signatures:                 signatures,
				AdditionalVariableMessages: variableMessages,
				Timestamps:                 timestamps,
			},
			AdditionalData: resultStatus,
			Version:        settings.EncodingVersion,
			Signature:      signature,
		}

		result, err = json.Marshal(voteSequence)
		if err != nil {
			return nil, nil, err
		}

	default:
		return nil, nil, errors.New("unexpected submission tag")
	}

	return result, resultStatus, nil
}

// Call forwards the call to the appropriate service and method
func validateOrExecuteInstruction(
	iData *instruction.DataFixed,
	variableMessages []hexutil.Bytes,
	signers []common.Address,
	dataProviderIndex map[common.Address]int,
	submissionTag types.SubmissionTag,
	signingPolicyBytes []byte,
) ([]byte, []byte, error) {
	var err error
	var result []byte
	var resultStatus []byte

	switch op.HashToOPType(iData.OPType) {
	case op.Reg:
		result, err = regInstruction(iData, submissionTag)

	case op.Wallet:
		result, resultStatus, err = walletInstruction(iData, variableMessages, signers, submissionTag)

	case op.XRP:
		result, err = xrpInstruction(iData, signers, dataProviderIndex, submissionTag)

	case op.FTDC:
		result, err = ftdcInstruction(iData, variableMessages, signers, dataProviderIndex, submissionTag, signingPolicyBytes)

	default:
		err = errors.New("invalid operation type")
	}

	return result, resultStatus, err
}

func regInstruction(data *instruction.DataFixed, submissionTag types.SubmissionTag) ([]byte, error) {
	var err error
	var result []byte

	switch submissionTag {
	case types.Threshold:
		switch op.HashToOPCommand(data.OPCommand) {
		case op.TEEAttestation:
			result, err = regutils.TeeAttestation(data)
		default:
			err = errors.New("Unknown OpCommand for REG OpType")
		}
	case types.End:
		switch op.HashToOPCommand(data.OPCommand) {
		case op.TEEAttestation:
			_, err = regutils.ValidateTeeAttestation(data.OriginalMessage)
		default:
			err = errors.New("Unknown OpCommand for REG OpType")
		}
	default:
		return nil, errors.New("unexpected submission tag")
	}

	return result, err
}

func walletInstruction(
	data *instruction.DataFixed,
	variableMessages []hexutil.Bytes,
	signers []common.Address,
	submissionTag types.SubmissionTag,
) ([]byte, []byte, error) {
	var err error
	var result []byte
	var resultStatus []byte

	switch submissionTag {
	case types.Threshold:
		switch op.HashToOPCommand(data.OPCommand) {
		case op.KeyGenerate:
			result, err = walletutils.NewWallet(data)

		case op.KeyDelete:
			err = walletutils.DeleteWallet(data)

		case op.KeyDataProviderRestore:
			result, resultStatus, err = walletutils.KeyDataProviderRestore(data, variableMessages, signers)

		default:
			err = errors.New("Unknown OpCommand for WALLET OpType")
		}
	case types.End:
		switch op.HashToOPCommand(data.OPCommand) {
		case op.KeyGenerate:
			err = walletutils.ValidateNewWallet(data)

		case op.KeyDelete:
			err = walletutils.ValidateDeleteWallet(data)

		case op.KeyDataProviderRestore:
			resultStatus, err = walletutils.ValidateKeyDataProviderRestore(data, variableMessages, signers)

		default:
			err = errors.New("Unknown OpCommand for WALLET OpType")
		}

	default:
		err = errors.New("unexpected submission tag")
	}

	return result, resultStatus, err
}

func xrpInstruction(data *instruction.DataFixed, signers []common.Address, dataProviderIndex map[common.Address]int, submissionTag types.SubmissionTag) ([]byte, error) {
	var err error
	var result []byte

	switch submissionTag {
	case types.Threshold:
		switch op.HashToOPCommand(data.OPCommand) {
		case op.Pay, op.Reissue:
			result, err = signutils.SignPaymentTransaction(data, signers, dataProviderIndex)

		default:
			err = errors.New("Unknown OpCommand for XRP OpType")
		}
	case types.End:
		switch op.HashToOPCommand(data.OPCommand) {
		case op.Pay, op.Reissue:
			// validation is just retrying to sign
			_, err = signutils.SignPaymentTransaction(data, signers, dataProviderIndex)

		default:
			err = errors.New("Unknown OpCommand for XRP OpType")
		}
	default:
		err = errors.New("unexpected submission tag")
	}

	return result, err
}

func ftdcInstruction(
	data *instruction.DataFixed,
	variableMessages []hexutil.Bytes,
	signers []common.Address,
	dataProviderIndex map[common.Address]int,
	submissionTag types.SubmissionTag,
	signingPolicyBytes []byte,
) ([]byte, error) {
	var err error
	var result []byte

	switch submissionTag {
	case types.Threshold:
		switch op.HashToOPCommand(data.OPCommand) {
		case op.Prove:
			result, err = ftdcutils.ValidateProve(data, variableMessages, signers, dataProviderIndex, signingPolicyBytes)

		default:
			err = errors.New("Unknown OpCommand for FTDC OpType")
		}
	case types.End:
		switch op.HashToOPCommand(data.OPCommand) {
		case op.Prove:
			_, err = ftdcutils.ValidateProve(data, variableMessages, signers, dataProviderIndex, signingPolicyBytes)

		default:
			err = errors.New("Unknown OpCommand for FTDC OpType")
		}
	default:
		err = errors.New("unexpected submission tag")
	}

	return result, err
}

func checkInstructionData(data *instruction.DataFixed) (*commonpolicy.SigningPolicy, error) {
	if data == nil {
		return nil, errors.New("instruction data is nil")
	}

	if data.TeeID.Hex() != node.TeeID().Hex() {
		return nil, errors.New("invalid TEE id")
	}

	activeSigningPolicy, err := policy.Storage.ActiveSigningPolicy()
	if err != nil {
		return nil, err
	}

	// Todo: not sure if this check is still correct? Is is just last policy now or?
	isActivePolicy := activeSigningPolicy.RewardEpochID == data.RewardEpochID
	isPreviousPolicy := activeSigningPolicy.RewardEpochID == data.RewardEpochID+1
	if !isActivePolicy && !isPreviousPolicy {
		return nil, errors.New("reward epoch id too old")
	}

	valid := op.IsValidPair(data.OPType, data.OPCommand)
	if !valid {
		return nil, errors.New("invalid command for operation type")
	}

	return activeSigningPolicy, nil
}
