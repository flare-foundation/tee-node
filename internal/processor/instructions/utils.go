package instructions

import (
	"slices"
	"sort"

	"github.com/flare-foundation/tee-node/internal/policy"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/op"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	commonpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/pkg/errors"
)

// validateRequestSize checks the size of the request fields,
func validateInstructionDataSize(data *instruction.DataFixed) error {
	ok := op.IsValid(data.OPType, data.OPCommand)
	if !ok {
		return errors.New("invalid OPType, OPCommand pair")
	}

	oc, ok := op.HashToOPCommandSafe(data.OPCommand)
	if !ok {
		return errors.New("invalid OPCommand")
	}

	maxMsgSize, ok := settings.MaxRequestSize[oc]
	if !ok {
		return errors.New("OPType not for instructions")
	}

	if len(data.OriginalMessage) > maxMsgSize.OriginalMessage {
		return errors.New("originalMessage exceeds maximum size")
	}
	if len(data.AdditionalFixedMessage) > maxMsgSize.AdditionalFixedMessage {
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

type pair struct {
	Type    op.Type
	Command op.Command
}

func checkDataProvidersThreshold(data *instruction.DataFixed, signers []common.Address, sPolicy *commonpolicy.SigningPolicy) (bool, []bool, error) {
	p := pair{op.HashToOPType(data.OPType), op.HashToOPCommand(data.OPCommand)}
	var threshold uint16
	isDataProvider := make([]bool, len(signers))
	for i, signer := range signers {
		if slices.Contains(sPolicy.Voters.Voters(), signer) {
			isDataProvider[i] = true
		}
	}

	switch p {
	case pair{op.Wallet, op.KeyDataProviderRestore}:
		return true, isDataProvider, nil

	case pair{op.FTDC, op.Prove}:
		request, err := types.DecodeFTDCRequest(data.OriginalMessage)
		if err != nil {
			return false, nil, err
		}

		totalWeight := policy.WeightOfSigners(sPolicy.Voters.Voters(), sPolicy)

		rh := request.Header
		if rh.ThresholdBIPS == 0 {
			threshold = sPolicy.Threshold
			break
		} else {
			threshold = (rh.ThresholdBIPS * totalWeight) / settings.MaxBIPS
			if (rh.ThresholdBIPS*totalWeight)%settings.MaxBIPS > 0 {
				threshold++
			}
		}

		if float64(rh.ThresholdBIPS) < float64(settings.MaxBIPS)*settings.FtdcMinimumDataProvidersThreshold {
			return false, nil, errors.New("data providers threshold too low")
		}
		if float64(rh.ThresholdBIPS) < float64(settings.MaxBIPS)*0.5 && rh.CosignersThreshold*2 <= uint64(len(rh.Cosigners)) {
			return false, nil, errors.New("one threshold should be above 50%")
		}

	default:
		threshold = sPolicy.Threshold
	}

	weight := policy.WeightOfSigners(signers, sPolicy)

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
