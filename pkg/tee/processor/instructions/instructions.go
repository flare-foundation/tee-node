package instructions

import (
	"slices"
	"tee-node/pkg/tee/node"
	"tee-node/pkg/tee/policy"
	"tee-node/pkg/tee/processor/instructions/signinginstruction"
	"tee-node/pkg/tee/processor/instructions/walletsinstruction"
	"tee-node/pkg/tee/settings"
	"tee-node/pkg/tee/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func ProcessInstruction(instructionData *instruction.DataFixed, variableMessages, signatures, cosignerVariableMessages, cosignerSignatures [][]byte) ([]byte, error) {
	var result []byte

	signingPolicy, err := CheckInstructionData(instructionData)
	if err != nil {
		return nil, err
	}
	err = ValidateInstructionDataSize(instructionData)
	if err != nil {
		return nil, err
	}

	signersDataProviders, err := SignaturesToSigners(instructionData, variableMessages, signatures)
	if err != nil {
		return nil, err
	}

	thresholdReached, err := CheckDataProvidersThreshold(instructionData, signersDataProviders, signingPolicy)
	if err != nil {
		return nil, err
	}
	if !thresholdReached {
		return nil, errors.New("threshold not reached")
	}

	cosigners, err := SignaturesToSigners(instructionData, cosignerVariableMessages, cosignerSignatures)
	if err != nil {
		return nil, err
	}

	result, err = ExecuteInstruction(instructionData, variableMessages, cosignerVariableMessages, signersDataProviders, cosigners)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Call forwards the call to the appropriate service and method
func ExecuteInstruction(instructionMessage *instruction.DataFixed, variableMessages [][]byte, cosignersVariableMessages [][]byte, signers, cosigners map[common.Address][]byte) ([]byte, error) {
	var err error
	var result []byte
	switch utils.OpHashToString(instructionMessage.OPType) {
	case "REG":
		result, err = executeRegInstruction(instructionMessage)

	case "WALLET":
		result, err = executeWalletInstruction(instructionMessage, variableMessages, cosignersVariableMessages, signers, cosigners)

	case "XRP":
		result, err = executeXrpInstruction(instructionMessage, cosigners)

	// case "BTC":
	// 	result, err = executeBtcInstruction(instructionMessage)

	case "FDC":
		result, err = executeFdcInstruction(instructionMessage)

	default:
		return nil, status.Error(codes.InvalidArgument, "invalid operation type")
	}
	if err != nil {
		return nil, err
	}

	return result, nil
}

func executeRegInstruction(instructionData *instruction.DataFixed) ([]byte, error) {
	switch utils.OpHashToString(instructionData.OPCommand) {
	case "AVAILABILITY_CHECK":
		return nil, errors.New("REG AVAILABILITY_CHECK command not implemented yet")

	// case "TO_PAUSE_FOR_UPGRADE":
	// 	return nil, errors.New("REG TO_PAUSE_FOR_UPGRADE command not implemented yet")

	// case "REPLICATE_FROM":
	// 	return nil, errors.New("REG REPLICATE_FROM command not implemented yet")

	default:
		return nil, errors.New("Unknown OpCommand for WALLET OpType")
	}
}

func executeWalletInstruction(instructionData *instruction.DataFixed, variableMessages [][]byte, cosignerVariableMessages [][]byte, signers, cosigners map[common.Address][]byte) ([]byte, error) {
	switch utils.OpHashToString(instructionData.OPCommand) {
	case "KEY_GENERATE":
		return walletsinstruction.NewWallet(instructionData)

	case "KEY_DELETE":
		return nil, walletsinstruction.DeleteWallet(instructionData)

	case "KEY_DATA_PROVIDER_RESTORE":
		return walletsinstruction.KeyDataProviderRestore(instructionData, variableMessages, cosignerVariableMessages, signers, cosigners)

	default:
		return nil, errors.New("Unknown OpCommand for WALLET OpType")
	}
}

func executeXrpInstruction(instructionData *instruction.DataFixed, cosigners map[common.Address][]byte) ([]byte, error) {
	switch utils.OpHashToString(instructionData.OPCommand) {
	case "PAY", "REISSUE":
		return signinginstruction.SignPaymentTransaction(instructionData, cosigners)

	default:
		return nil, errors.New("Unknown OpCommand for XRP OpType")
	}
}

// func executeBtcInstruction(instructionData *instruction.DataFixed) ([]byte, error) {
// 	switch utils.OpHashToString(instructionData.OPCommand) {
// 	case "PAY":
// 		return nil, errors.New("BTC PAY command not implemented yet")

// 	case "REISSUE":
// 		return nil, errors.New("BTC REISSUE command not implemented yet")

// 	default:
// 		return nil, errors.New("Unknown OpCommand for BTC OpType")

// 	}
// }

func executeFdcInstruction(instructionData *instruction.DataFixed) ([]byte, error) {
	switch utils.OpHashToString(instructionData.OPCommand) {
	case "PROVE":
		return nil, errors.New("FDC PROVE command not implemented yet")

	default:
		return nil, errors.New("Unknown OpCommand for FDC OpType")
	}
}

func CheckInstructionData(instructionData *instruction.DataFixed) (*policy.SigningPolicy, error) {
	if instructionData == nil {
		return nil, errors.New("instruction data is nil")
	}

	if instructionData.TeeID.Hex() != node.GetTeeId().Hex() {
		return nil, errors.New("invalid TEE id")
	}

	activeSigningPolicy, err := policy.GetActiveSigningPolicy()
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

// IsValidSubCommand checks if the OpType and Command is valid for a given operation type
func isValidCommand(op, command string) bool {
	validCommands, exists := settings.InstructionOperations[op]
	if !exists {
		return false
	}

	if _, exists := validCommands[command]; exists {
		return true
	}
	return false
}

// validateRequestSize checks the size of the request fields
func ValidateInstructionDataSize(instructionData *instruction.DataFixed) error {
	// Check the size of the different messages
	messageSizeConstraint := settings.MaxRequestSize[utils.OpHashToString(instructionData.OPType)][utils.OpHashToString(instructionData.OPCommand)]
	if len(instructionData.OriginalMessage) > messageSizeConstraint.MaxOriginalMessageSize {
		return status.Error(codes.InvalidArgument, "originalMessage exceeds maximum size")
	}
	if len(instructionData.AdditionalFixedMessage) > messageSizeConstraint.MaxAdditionalFixedMessageSize {
		return status.Error(codes.InvalidArgument, "additionalFixedMessage exceeds maximum size")
	}

	return nil
}

func SignaturesToSigners(instructionDataFixed *instruction.DataFixed, variableMessages, signatures [][]byte) (map[common.Address][]byte, error) {
	if len(variableMessages) != 0 && len(variableMessages) != len(signatures) {
		return nil, errors.New("the number of variable messages does not match the number of signatures")
	}

	signers := make(map[common.Address][]byte)
	for i, signature := range signatures {
		instructionData := instruction.Data{DataFixed: *instructionDataFixed}
		if len(variableMessages) != 0 {
			instructionData.AdditionalVariableMessage = variableMessages[i]
		}

		hash, err := instructionData.HashForSigning()
		if err != nil {
			return nil, err
		}
		signer, err := utils.SignatureToSignersAddress(hash[:], signature)
		if err != nil {
			return nil, err
		}
		if _, ok := signers[signer]; ok {
			return nil, errors.New("double signing")
		}

		signers[signer] = signature
	}

	return signers, nil
}

type OPTypeCommand struct {
	Type    string
	Command string
}

func CheckDataProvidersThreshold(instructionDataFixed *instruction.DataFixed, signers map[common.Address][]byte, signingPolicy *policy.SigningPolicy) (bool, error) {
	oPTypeCommand := OPTypeCommand{utils.OpHashToString(instructionDataFixed.OPType), utils.OpHashToString(instructionDataFixed.OPCommand)}
	switch oPTypeCommand {
	case OPTypeCommand{"WALLET", "KEY_DATA_PROVIDER_RESTORE"}:
		return true, nil // todo: or add threshold?
	default:
		for signer := range signers {
			if !slices.Contains(signingPolicy.Voters, signer) {
				return false, errors.New("signed by an entity not in the signing policy")
			}
		}

		weight := policy.WeightOfSigners(signers, signingPolicy)

		return weight >= signingPolicy.Threshold, nil
	}
}
