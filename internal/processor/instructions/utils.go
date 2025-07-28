package instructions

import (
	"slices"
	"sort"

	"github.com/flare-foundation/tee-node/internal/policy"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	commonpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/pkg/errors"
)

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
func validateInstructionDataSize(instructionData *instruction.DataFixed) error {
	// Check the size of the different messages
	messageSizeOPTypeMap, ok := settings.MaxRequestSize[utils.OpHashToString(instructionData.OpType)]
	if !ok {
		return errors.New("OPType not defined")
	}
	messageSizeConstraint, ok := messageSizeOPTypeMap[utils.OpHashToString(instructionData.OpCommand)]
	if !ok {
		return errors.New("OPCommand not defined")
	}
	if len(instructionData.OriginalMessage) > messageSizeConstraint.MaxOriginalMessageSize {
		return errors.New("originalMessage exceeds maximum size")
	}
	if len(instructionData.AdditionalFixedMessage) > messageSizeConstraint.MaxAdditionalFixedMessageSize {
		return errors.New("additionalFixedMessage exceeds maximum size")
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

type OPTypeCommand struct {
	Type    string
	Command string
}

func checkDataProvidersThreshold(instructionDataFixed *instruction.DataFixed, signers []common.Address, signingPolicy *commonpolicy.SigningPolicy) (bool, []bool, error) {
	oPTypeCommand := OPTypeCommand{utils.OpHashToString(instructionDataFixed.OpType), utils.OpHashToString(instructionDataFixed.OpCommand)}
	var threshold uint16
	isDataProvider := make([]bool, len(signers))
	for i, signer := range signers {
		if slices.Contains(signingPolicy.Voters.Voters(), signer) {
			isDataProvider[i] = true
		}
	}

	switch oPTypeCommand {
	case OPTypeCommand{"WALLET", "KEY_DATA_PROVIDER_RESTORE"}:
		return true, isDataProvider, nil

	case OPTypeCommand{"FTDC", "PROVE"}:
		proveRequest, err := types.DecodeFTDCRequest(instructionDataFixed.OriginalMessage)
		if err != nil {
			return false, nil, err
		}

		totalWeight := policy.WeightOfSigners(signingPolicy.Voters.Voters(), signingPolicy)

		rh := proveRequest.Header
		if rh.ThresholdBIPS == 0 {
			threshold = signingPolicy.Threshold
		} else {
			threshold = (rh.ThresholdBIPS * totalWeight) / settings.BIPSConstant
			if (rh.ThresholdBIPS*totalWeight)%settings.BIPSConstant > 0 {
				threshold++
			}
		}

		if float64(rh.ThresholdBIPS) < float64(settings.BIPSConstant)*settings.FtdcMinimumDataProvidersThreshold {
			return false, nil, errors.New("data providers threshold too low")
		}
		if float64(rh.ThresholdBIPS) < float64(settings.BIPSConstant)*0.5 && rh.CosignersThreshold*2 <= uint64(len(rh.Cosigners)) {
			return false, nil, errors.New("one threshold should be above 50%")
		}

	default:
		threshold = signingPolicy.Threshold
	}

	weight := policy.WeightOfSigners(signers, signingPolicy)

	return weight > threshold, isDataProvider, nil
}

func voteHash(instructionDataFixed *instruction.DataFixed, signatures, variableMessages []hexutil.Bytes, signers []common.Address, timestamps []uint64) (common.Hash, error) {
	if len(signatures) != len(timestamps) {
		return common.Hash{}, errors.New("number of signatures and timestamps do not match")
	}
	if len(signers) != len(timestamps) {
		return common.Hash{}, errors.New("number of signers and timestamps do not match")
	}
	if len(signers) != len(variableMessages) {
		return common.Hash{}, errors.New("number of variableMessages and timestamps do not match")
	}

	order := make([]int, len(timestamps))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool { return timestamps[i] < timestamps[j] })

	voteHash, err := instructionDataFixed.InitialVoteHash()
	if err != nil {
		return common.Hash{}, err
	}
	for i := range order {
		voteHash, err = instruction.NextVoteHash(voteHash, uint64(i), signatures[i], variableMessages[i], timestamps[i])
		if err != nil {
			return common.Hash{}, err
		}
	}

	return voteHash, nil
}
