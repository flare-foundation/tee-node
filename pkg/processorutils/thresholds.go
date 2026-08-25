package processorutils

import (
	"errors"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	cpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"

	"github.com/flare-foundation/tee-node/internal/policy"
	"github.com/flare-foundation/tee-node/pkg/fdc"
	"github.com/flare-foundation/tee-node/pkg/utils"
)

const maxBIPS = 10000

const fdcMinimumThresholdBIPS = 4000

// CheckThresholds checks that data provider threshold and cosigner threshold are reached.
func CheckThresholds(data *instruction.DataFixed, signers []common.Address, sPolicy *cpolicy.SigningPolicy) error {
	if utils.HasDuplicateAddresses(data.Cosigners) {
		return errors.New("cosigner list contains duplicate addresses")
	}

	err := checkCosigners(signers, data.Cosigners, data.CosignersThreshold)
	if err != nil {
		return err
	}

	dpThreshold, err := dataProvidersThreshold(data, sPolicy)
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

// dataProvidersThreshold returns the weight that the signing data providers must
// strictly exceed.
//
// The signing policy's own threshold governs every instruction, matching what the
// Relay enforces. The one exception is an FDC2 request that names a non-zero
// thresholdBIPS, which the Relay likewise overrides with a share of total weight.
func dataProvidersThreshold(data *instruction.DataFixed, sPolicy *cpolicy.SigningPolicy) (uint16, error) {
	p := pair{op.HashToOPType(data.OPType), op.HashToOPCommand(data.OPCommand)}
	switch p {
	case pair{op.FDC2, op.Prove}:
		request, err := fdc.DecodeRequest(data.OriginalMessage)
		if err != nil {
			return 0, err
		}
		rh := request.Header

		if rh.ThresholdBIPS == 0 {
			return policyThreshold(sPolicy)
		}

		if rh.ThresholdBIPS < fdcMinimumThresholdBIPS {
			return 0, errors.New("data providers threshold too low")
		}
		if rh.ThresholdBIPS < maxBIPS/2 && data.CosignersThreshold*2 <= uint64(len(data.Cosigners)) {
			return 0, errors.New("one threshold should be above 50%")
		}
		if rh.ThresholdBIPS >= maxBIPS {
			return 0, errors.New("data providers threshold too high")
		}

		return computeThreshold(sPolicy.Voters.TotalWeight, rh.ThresholdBIPS), nil

	default:
		return policyThreshold(sPolicy)
	}
}

// policyThreshold reads the threshold off the signing policy.
//
// Zero is rejected rather than passed on: nothing bounds the field on an
// operator-supplied initial policy, and acceptance is strict, so a zero would
// admit any single data provider.
func policyThreshold(sPolicy *cpolicy.SigningPolicy) (uint16, error) {
	if sPolicy.Threshold == 0 {
		return 0, errors.New("signing policy threshold is zero")
	}

	return sPolicy.Threshold, nil
}

// computeThreshold matches the on-chain threshold override, Relay.sol's
// div(mul(totalWeight, overrideBIPS), THRESHOLD_BIPS).
// It is assumed that 0 <= bips <= 10000.
//
// Floor, not ceiling: the acceptance test is strict on both sides (weight >
// threshold), so rounding up here would demand one extra weight unit and reject
// signature sets the Relay accepts.
func computeThreshold(total uint16, bips uint16) uint16 {
	t64 := uint64(total)
	b64 := uint64(bips)

	return uint16(t64 * b64 / maxBIPS) //nolint:gosec
}
