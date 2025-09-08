package processorutils

import (
	"errors"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	cpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"

	"github.com/flare-foundation/tee-node/pkg/ftdc"
	"github.com/flare-foundation/tee-node/pkg/policy"
)

const maxBIPS = 10000

const ftdcMinimumThresholdBIPS = 4000

// CheckThresholds checks that data provider threshold and cosigner threshold are reached.
func CheckThresholds(data *instruction.DataFixed, signers []common.Address, sPolicy *cpolicy.SigningPolicy) error {
	err := checkCosigners(signers, data.Cosigners, data.CosignersThreshold)
	if err != nil {
		return err
	}

	dpThreshold, err := dataProvidersThreshold(data, sPolicy.Voters.TotalWeight)
	if err != nil {
		return err
	}

	weight := policy.WeightOfSigners(signers, sPolicy)
	if weight <= dpThreshold {
		return errors.New("data providers threshold not reached")
	}

	for _, signer := range signers {
		isCosigner := slices.Contains(data.Cosigners, signer)
		voterIndex := sPolicy.Voters.VoterIndex(signer)
		isDataProvider := voterIndex != -1
		if !isCosigner && !isDataProvider {
			return errors.New("signed by an entity that is neither data provider nor cosigner")
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

type pair struct {
	Type    op.Type
	Command op.Command
}

func dataProvidersThreshold(data *instruction.DataFixed, totalWeight uint16) (uint16, error) {
	var threshold uint16
	p := pair{op.HashToOPType(data.OPType), op.HashToOPCommand(data.OPCommand)}
	switch p {
	case pair{op.Wallet, op.KeyDataProviderRestore}:
		threshold = 0 // condition (weight >= threshold) always true

	case pair{op.FTDC, op.Prove}:
		request, err := ftdc.DecodeRequest(data.OriginalMessage)
		if err != nil {
			return 0, err
		}
		rh := request.Header

		if rh.ThresholdBIPS == 0 {
			threshold = computeThreshold(totalWeight, maxBIPS/2)
			break
		}

		if rh.ThresholdBIPS < ftdcMinimumThresholdBIPS {
			return 0, errors.New("data providers threshold too low")
		}
		if rh.ThresholdBIPS < maxBIPS/2 && data.CosignersThreshold*2 <= uint64(len(data.Cosigners)) {
			return 0, errors.New("one threshold should be above 50%")
		}

		threshold = computeThreshold(totalWeight, rh.ThresholdBIPS)

	default:
		threshold = computeThreshold(totalWeight, maxBIPS/2)
	}

	return threshold, nil
}

// computeThreshold matches the computation of the threshold for signing policy.
// It is assumed that 0 <= bips <= 10000.
func computeThreshold(total uint16, bips uint16) uint16 {
	t64 := uint64(total)
	b64 := uint64(bips)
	t := t64 * b64 / maxBIPS

	if (t64*b64)%maxBIPS != 0 {
		t++
	}

	return uint16(t) //nolint:gosec
}
