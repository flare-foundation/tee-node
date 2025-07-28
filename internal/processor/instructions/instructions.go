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
	"github.com/flare-foundation/tee-node/pkg/utils"

	commonpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"

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

	thresholdReached, isSignerDataProvider, err := checkDataProvidersThreshold(instructionData, signers, signingPolicy)
	if err != nil {
		return nil, nil, err
	}
	if !thresholdReached {
		return nil, nil, errors.New("threshold not reached")
	}

	executionResult, resultStatus, err := validateOrExecuteInstruction(instructionData, variableMessages, signers, isSignerDataProvider, submissionTag)
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
				InstructionId:              instructionData.InstructionId,
				InstructionHash:            instructionHash,
				RewardEpochId:              instructionData.RewardEpochId,
				TeeId:                      instructionData.TeeId,
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
	instructionMessage *instruction.DataFixed,
	variableMessages []hexutil.Bytes,
	signers []common.Address,
	isSignerDataProvider []bool,
	submissionTag types.SubmissionTag,
) ([]byte, []byte, error) {
	var err error
	var result []byte
	var resultStatus []byte

	switch utils.OpHashToString(instructionMessage.OpType) {
	case "REG":
		result, err = regInstruction(instructionMessage, submissionTag)

	case "WALLET":
		result, resultStatus, err = walletInstruction(instructionMessage, variableMessages, signers, isSignerDataProvider, submissionTag)

	case "XRP":
		result, err = xrpInstruction(instructionMessage, signers, isSignerDataProvider, submissionTag)

	case "FTDC":
		result, err = ftdcInstruction(instructionMessage, variableMessages, signers, isSignerDataProvider, submissionTag)

	default:
		err = errors.New("invalid operation type")
	}

	return result, resultStatus, err
}

func regInstruction(instructionData *instruction.DataFixed, submissionTag types.SubmissionTag) ([]byte, error) {
	var err error
	var result []byte

	switch submissionTag {
	case types.Threshold:
		switch utils.OpHashToString(instructionData.OpCommand) {
		case "TEE_ATTESTATION":
			result, err = regutils.TeeAttestation(instructionData)
		default:
			err = errors.New("Unknown OpCommand for REG OpType")
		}
	case types.End:
		switch utils.OpHashToString(instructionData.OpCommand) {
		case "TEE_ATTESTATION":
			_, err = regutils.ValidateTeeAttestation(instructionData.OriginalMessage)
		default:
			err = errors.New("Unknown OpCommand for REG OpType")
		}
	default:
		return nil, errors.New("unexpected submission tag")
	}

	return result, err
}

func walletInstruction(
	instructionData *instruction.DataFixed,
	variableMessages []hexutil.Bytes,
	signers []common.Address,
	isSignerDataProvider []bool,
	submissionTag types.SubmissionTag,
) ([]byte, []byte, error) {
	var err error
	var result []byte
	var resultStatus []byte

	switch submissionTag {
	case types.Threshold:
		switch utils.OpHashToString(instructionData.OpCommand) {
		case "KEY_GENERATE":
			result, err = walletutils.NewWallet(instructionData)

		case "KEY_DELETE":
			err = walletutils.DeleteWallet(instructionData)

		case "KEY_DATA_PROVIDER_RESTORE":
			result, resultStatus, err = walletutils.KeyDataProviderRestore(instructionData, variableMessages, signers)

		default:
			err = errors.New("Unknown OpCommand for WALLET OpType")
		}
	case types.End:
		switch utils.OpHashToString(instructionData.OpCommand) {
		case "KEY_GENERATE":
			err = walletutils.ValidateNewWallet(instructionData)

		case "KEY_DELETE":
			err = walletutils.ValidateDeleteWallet(instructionData)

		case "KEY_DATA_PROVIDER_RESTORE":
			resultStatus, err = walletutils.ValidateKeyDataProviderRestore(instructionData, variableMessages, signers)

		default:
			err = errors.New("Unknown OpCommand for WALLET OpType")
		}

	default:
		err = errors.New("unexpected submission tag")
	}

	return result, resultStatus, err
}

func xrpInstruction(instructionData *instruction.DataFixed, signers []common.Address, isSignerDataProvider []bool, submissionTag types.SubmissionTag) ([]byte, error) {
	var err error
	var result []byte

	switch submissionTag {
	case types.Threshold:
		switch utils.OpHashToString(instructionData.OpCommand) {
		case "PAY", "REISSUE":
			result, err = signutils.SignPaymentTransaction(instructionData, signers, isSignerDataProvider)

		default:
			err = errors.New("Unknown OpCommand for XRP OpType")
		}
	case types.End:
		switch utils.OpHashToString(instructionData.OpCommand) {
		case "PAY", "REISSUE":
			// validation is just retrying to sign
			_, err = signutils.SignPaymentTransaction(instructionData, signers, isSignerDataProvider)

		default:
			err = errors.New("Unknown OpCommand for XRP OpType")
		}
	default:
		err = errors.New("unexpected submission tag")
	}

	return result, err
}

func ftdcInstruction(instructionData *instruction.DataFixed, variableMessages []hexutil.Bytes, signers []common.Address, isSignerDataProvider []bool, submissionTag types.SubmissionTag) ([]byte, error) {
	var err error
	var result []byte

	switch submissionTag {
	case types.Threshold:
		switch utils.OpHashToString(instructionData.OpCommand) {
		case "PROVE":
			result, err = ftdcutils.ValidateProve(instructionData, variableMessages, signers, isSignerDataProvider)

		default:
			err = errors.New("Unknown OpCommand for FTDC OpType")
		}
	case types.End:
		switch utils.OpHashToString(instructionData.OpCommand) {
		case "PROVE":
			_, err = ftdcutils.ValidateProve(instructionData, variableMessages, signers, isSignerDataProvider)

		default:
			err = errors.New("Unknown OpCommand for FTDC OpType")
		}
	default:
		err = errors.New("unexpected submission tag")
	}

	return result, err
}

func checkInstructionData(instructionData *instruction.DataFixed) (*commonpolicy.SigningPolicy, error) {
	if instructionData == nil {
		return nil, errors.New("instruction data is nil")
	}

	if instructionData.TeeId.Hex() != node.GetTeeId().Hex() {
		return nil, errors.New("invalid TEE id")
	}

	activeSigningPolicy, err := policy.Storage.ActiveSigningPolicy()
	if err != nil {
		return nil, err
	}

	// Todo: not sure if this check is still correct? Is is just last policy now or?
	isActivePolicy := activeSigningPolicy.RewardEpochID == instructionData.RewardEpochId
	isPreviousPolicy := activeSigningPolicy.RewardEpochID == instructionData.RewardEpochId+1
	if !isActivePolicy && !isPreviousPolicy {
		return nil, errors.New("reward epoch id too old")
	}

	valid := isValidCommand(utils.OpHashToString(instructionData.OpType), utils.OpHashToString(instructionData.OpCommand))
	if !valid {
		return nil, errors.New("invalid command for operation type")
	}

	return activeSigningPolicy, nil
}
