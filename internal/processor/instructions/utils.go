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
	cpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"

	"github.com/pkg/errors"
)

// validateRequestSize checks the size of the request fields,
func validateInstructionDataSize(data *instruction.DataFixed) error {
	ok := op.IsValidPair(data.OPType, data.OPCommand)
	if !ok {
		return errors.New("invalid OPType, OPCommand pair")
	}

	oc := op.HashToOPCommand(data.OPCommand)

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

func checkThresholds(data *instruction.DataFixed, signers []common.Address, sPolicy *cpolicy.SigningPolicy) error {
	err := checkCosigners(signers, data.Cosigners, data.CosignersThreshold)
	if err != nil {
		return err
	}

	dpThreshold, err := setDataProvidersThreshold(data, sPolicy)
	if err != nil {
		return err
	}

	weight := policy.WeightOfSigners(signers, sPolicy)
	if weight < dpThreshold {
		return errors.New("data providers threshold not reached")
	}

	for _, signer := range signers {
		isCosigner := slices.Contains(data.Cosigners, signer)
		voterIndex := sPolicy.Voters.VoterIndex(signer)
		isDataProvider := voterIndex != -1
		if !isCosigner && !isDataProvider {
			return errors.New("signed by an entity that is nether data provider nor cosigner")
		}
	}

	return nil
}

func checkCosigners(signers []common.Address, allCosigners []common.Address, threshold uint64) error {
	countCosigners := uint64(0)
	for _, cosigner := range allCosigners {
		if ok := slices.Contains(signers, cosigner); ok {
			countCosigners++
		}
	}

	if countCosigners < threshold {
		return errors.New("cosigners threshold not reached")
	}

	return nil
}

func setDataProvidersThreshold(data *instruction.DataFixed, sPolicy *cpolicy.SigningPolicy) (uint16, error) {
	var dpThreshold uint16
	p := pair{op.HashToOPType(data.OPType), op.HashToOPCommand(data.OPCommand)}
	switch p {
	case pair{op.Wallet, op.KeyDataProviderRestore}:
		dpThreshold = 0 // condition (weight >= threshold) always true

	case pair{op.FTDC, op.Prove}:
		request, err := types.DecodeFTDCRequest(data.OriginalMessage)
		if err != nil {
			return 0, err
		}
		rh := request.Header
		if rh.ThresholdBIPS == 0 {
			dpThreshold = sPolicy.Threshold + 1 // plus 1 to have condition (weight >= threshold)
			break
		}

		totalWeight := policy.WeightOfSigners(sPolicy.Voters.Voters(), sPolicy)
		dpThreshold = (rh.ThresholdBIPS*totalWeight)/settings.MaxBIPS + 1 // plus 1 to have condition (weight >= threshold)
		if (rh.ThresholdBIPS*totalWeight)%settings.MaxBIPS > 0 {
			dpThreshold++
		}

		if float64(rh.ThresholdBIPS) < float64(settings.MaxBIPS)*settings.FtdcMinimumDataProvidersThreshold {
			return 0, errors.New("data providers threshold too low")
		}
		if float64(rh.ThresholdBIPS) < float64(settings.MaxBIPS)*0.5 && data.CosignersThreshold*2 <= uint64(len(data.Cosigners)) {
			return 0, errors.New("one threshold should be above 50%")
		}

	default:
		dpThreshold = sPolicy.Threshold + 1 // plus 1 to have condition (weight >= threshold)
	}

	return dpThreshold, nil
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
