package instructions

import (
	"encoding/json"

	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/policy"
	"github.com/flare-foundation/tee-node/internal/processor/instructions/regutils"
	"github.com/flare-foundation/tee-node/internal/processor/instructions/signutils"
	"github.com/flare-foundation/tee-node/internal/processor/instructions/walletutils"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

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

	executionResult, resultStatus, err := validateExecuteInstruction(instructionData, variableMessages, signers, isSignerDataProvider, submissionTag)
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

		signerSequence := types.SignerSequence{
			Data: types.SignerSequenceData{
				VoteHash:                   voteHash,
				InstructionId:              instructionData.InstructionID,
				InstructionHash:            instructionHash,
				RewardEpochId:              uint32(instructionData.RewardEpochID.Uint64()),
				TeeId:                      instructionData.TeeID,
				Signatures:                 signatures,
				AdditionalVariableMessages: variableMessages,
				Timestamps:                 timestamps,
			},
			Signature: signature,
		}

		result, err = json.Marshal(signerSequence)
		if err != nil {
			return nil, nil, err
		}

	default:
		return nil, nil, errors.New("unexpected submission tag")
	}

	return result, resultStatus, nil
}

// Call forwards the call to the appropriate service and method
func validateExecuteInstruction(
	instructionMessage *instruction.DataFixed,
	variableMessages []hexutil.Bytes,
	signers []common.Address,
	isSignerDataProvider []bool,
	submissionTag types.SubmissionTag,
) ([]byte, []byte, error) {
	var err error
	var result []byte
	var resultStatus []byte

	switch utils.OpHashToString(instructionMessage.OPType) {
	case "REG":
		result, err = regInstruction(instructionMessage, submissionTag)

	case "WALLET":
		result, resultStatus, err = walletInstruction(instructionMessage, variableMessages, signers, isSignerDataProvider, submissionTag)

	case "XRP":
		result, err = xrpInstruction(instructionMessage, signers, isSignerDataProvider, submissionTag)

	case "FDC":
		result, err = fdcInstruction(instructionMessage, submissionTag)

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
		switch utils.OpHashToString(instructionData.OPCommand) {
		case "TEE_ATTESTATION":
			result, err = regutils.TeeAttestation(instructionData)
		default:
			err = errors.New("Unknown OpCommand for REG OpType")
		}
	case types.End:
		switch utils.OpHashToString(instructionData.OPCommand) {
		case "TEE_ATTESTATION":
			err = regutils.ValidateTeeAttestation(instructionData)
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
		switch utils.OpHashToString(instructionData.OPCommand) {
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
		switch utils.OpHashToString(instructionData.OPCommand) {
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
		switch utils.OpHashToString(instructionData.OPCommand) {
		case "PAY", "REISSUE":
			result, err = signutils.SignPaymentTransaction(instructionData, signers, isSignerDataProvider)

		default:
			err = errors.New("Unknown OpCommand for XRP OpType")
		}
	case types.End:
		switch utils.OpHashToString(instructionData.OPCommand) {
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

func fdcInstruction(instructionData *instruction.DataFixed, submissionTag types.SubmissionTag) ([]byte, error) {
	switch submissionTag {
	case types.Threshold:
		switch utils.OpHashToString(instructionData.OPCommand) {
		case "PROVE":
			return nil, errors.New("FDC PROVE command not implemented yet")

		default:
			return nil, errors.New("Unknown OpCommand for FDC OpType")
		}
	case types.End:
		switch utils.OpHashToString(instructionData.OPCommand) {
		case "PROVE":
			return nil, errors.New("FDC PROVE command not implemented yet")

		default:
			return nil, errors.New("Unknown OpCommand for FDC OpType")
		}
	default:
		return nil, errors.New("unexpected submission tag")
	}
}

func checkInstructionData(instructionData *instruction.DataFixed) (*policy.SigningPolicy, error) {
	if instructionData == nil {
		return nil, errors.New("instruction data is nil")
	}

	if instructionData.TeeID.Hex() != node.GetTeeId().Hex() {
		return nil, errors.New("invalid TEE id")
	}

	activeSigningPolicy, err := policy.Storage.GetActiveSigningPolicy()
	if err != nil {
		return nil, err
	}

	isActivePolicy := activeSigningPolicy.RewardEpochId == uint32(instructionData.RewardEpochID.Uint64())
	isPreviousPolicy := activeSigningPolicy.RewardEpochId == uint32(instructionData.RewardEpochID.Uint64())+1
	if !isActivePolicy && !isPreviousPolicy {
		return nil, errors.New("reward epoch id too old")
	}

	valid := isValidCommand(utils.OpHashToString(instructionData.OPType), utils.OpHashToString(instructionData.OPCommand))
	if !valid {
		return nil, errors.New("invalid command for operation type")
	}

	return activeSigningPolicy, nil
}
