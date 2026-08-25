package processorutils

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	cpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/fdc2"
	"github.com/flare-foundation/go-flare-common/pkg/voters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/flare-foundation/tee-node/pkg/fdc"
)

func TestComputeThreshold(t *testing.T) {
	// exact division
	assert.Equal(t, uint16(50), computeThreshold(100, maxBIPS/2))
	// floors on remainder, matching Relay.sol's div(mul(total, bips), 10000);
	// acceptance is strict (weight > threshold), so 2 of 3 still passes
	assert.Equal(t, uint16(1), computeThreshold(3, maxBIPS/2))
	assert.Equal(t, uint16(50), computeThreshold(101, maxBIPS/2))
	// 9999 BIPS with all weight must remain reachable — a ceiling would make it
	// impossible, which is why the contract floors
	assert.Equal(t, uint16(99), computeThreshold(100, maxBIPS-1))
	// zero bips
	assert.Equal(t, uint16(0), computeThreshold(42, 0))
}

func TestDataProvidersThreshold(t *testing.T) {
	// 55 is neither floor nor ceil of half the total weight, so a recomputed
	// threshold cannot be mistaken for the policy's own
	sPolicy, _ := newPolicy(t, []uint16{50, 30, 20}, 55)
	cosigners := []common.Address{
		common.HexToAddress("0x15"),
		common.HexToAddress("0x16"),
		common.HexToAddress("0x17"),
		common.HexToAddress("0x18"),
	}

	t.Run("wallet restore uses the policy threshold", func(t *testing.T) {
		data := &instruction.DataFixed{
			OPType:    op.Wallet.Hash(),
			OPCommand: op.KeyDataProviderRestore.Hash(),
		}

		threshold, err := dataProvidersThreshold(data, sPolicy)
		assert.NoError(t, err)
		assert.Equal(t, uint16(55), threshold)
	})

	t.Run("op different from F_FDC2/Prove uses the policy threshold", func(t *testing.T) {
		data := &instruction.DataFixed{
			OPType:    op.XRP.Hash(),
			OPCommand: op.Pay.Hash(),
		}

		threshold, err := dataProvidersThreshold(data, sPolicy)
		assert.NoError(t, err)
		assert.Equal(t, uint16(55), threshold)
	})

	t.Run("FDC request with invalid message should fail", func(t *testing.T) {
		data := &instruction.DataFixed{
			OPType:          op.FDC2.Hash(),
			OPCommand:       op.Prove.Hash(),
			OriginalMessage: []byte("invalid"),
		}

		threshold, err := dataProvidersThreshold(data, sPolicy)
		assert.Error(t, err)
		assert.Equal(t, uint16(0), threshold)
	})

	t.Run("FDC message with zero threshold uses the policy threshold", func(t *testing.T) {
		data := buildFDCData(t, 0, nil, 0)

		threshold, err := dataProvidersThreshold(data, sPolicy)
		assert.NoError(t, err)
		assert.Equal(t, uint16(55), threshold)
	})

	t.Run("FDC request with threshold too low should fail", func(t *testing.T) {
		data := buildFDCData(t, fdcMinimumThresholdBIPS-1, nil, 0)

		_, err := dataProvidersThreshold(data, sPolicy)
		assert.EqualError(t, err, "data providers threshold too low")
	})

	t.Run("FDC request with cosigner threshold below 50% should fail", func(t *testing.T) {
		data := buildFDCData(t, maxBIPS/2-1, cosigners, 2)

		_, err := dataProvidersThreshold(data, sPolicy)
		assert.EqualError(t, err, "one threshold should be above 50%")
	})

	t.Run("FDC request with threshold too high should fail", func(t *testing.T) {
		data := buildFDCData(t, maxBIPS, nil, 0)

		_, err := dataProvidersThreshold(data, sPolicy)
		assert.EqualError(t, err, "data providers threshold too high")
	})

	t.Run("FDC valid threshold overrides the policy with the provided bips", func(t *testing.T) {
		data := buildFDCData(t, maxBIPS*0.6, cosigners[:2], 1)

		threshold, err := dataProvidersThreshold(data, sPolicy)
		assert.NoError(t, err)
		assert.Equal(t, uint16(60), threshold)
	})

	t.Run("zero policy threshold is rejected", func(t *testing.T) {
		zeroPolicy, _ := newPolicy(t, []uint16{50, 30, 20}, 0)

		_, err := dataProvidersThreshold(&instruction.DataFixed{
			OPType:    op.XRP.Hash(),
			OPCommand: op.Pay.Hash(),
		}, zeroPolicy)
		assert.EqualError(t, err, "signing policy threshold is zero")

		_, err = dataProvidersThreshold(buildFDCData(t, 0, nil, 0), zeroPolicy)
		assert.EqualError(t, err, "signing policy threshold is zero")
	})

	t.Run("a non-zero bips threshold does not consult the policy", func(t *testing.T) {
		zeroPolicy, _ := newPolicy(t, []uint16{50, 30, 20}, 0)

		threshold, err := dataProvidersThreshold(buildFDCData(t, maxBIPS*0.6, cosigners[:2], 1), zeroPolicy)
		assert.NoError(t, err)
		assert.Equal(t, uint16(60), threshold)
	})
}

func TestCheckCosigners(t *testing.T) {
	allCosigners := []common.Address{common.HexToAddress("0x1"), common.HexToAddress("0x2"), common.HexToAddress("0x3")}

	t.Run("threshold not reached", func(t *testing.T) {
		signers := []common.Address{allCosigners[0], common.HexToAddress("0x4")}
		err := checkCosigners(signers, allCosigners, 2)
		assert.EqualError(t, err, "cosigners threshold not reached")
	})

	t.Run("threshold reached", func(t *testing.T) {
		err := checkCosigners(allCosigners[:2], allCosigners, 2)
		assert.NoError(t, err)
	})
}

func TestCheckThresholds(t *testing.T) {
	weights := []uint16{50, 30, 20}
	policy, voters := newPolicy(t, weights, 55)
	cosigners := []common.Address{common.HexToAddress("0x65"), common.HexToAddress("0x66")}

	newData := func(cosignerThreshold uint64) *instruction.DataFixed {
		return &instruction.DataFixed{
			OPType:             op.XRP.Hash(),
			OPCommand:          op.Pay.Hash(),
			Cosigners:          cosigners,
			CosignersThreshold: cosignerThreshold,
		}
	}

	t.Run("fails when cosigner threshold not met", func(t *testing.T) {
		data := newData(2)
		signers := []common.Address{voters[0], cosigners[0]}

		err := CheckThresholds(data, signers, policy)
		assert.EqualError(t, err, "cosigners threshold not reached")
	})

	t.Run("fails when data provider threshold not reached", func(t *testing.T) {
		data := newData(0)
		signers := []common.Address{voters[0]} // weight 50 does not exceed the policy threshold of 55

		err := CheckThresholds(data, signers, policy)
		assert.EqualError(t, err, "data providers threshold not reached")
	})

	t.Run("weight equal to the threshold is not enough", func(t *testing.T) {
		boundary, boundaryVoters := newPolicy(t, weights, 80)

		err := CheckThresholds(newData(0), []common.Address{boundaryVoters[0], boundaryVoters[1]}, boundary)
		assert.EqualError(t, err, "data providers threshold not reached")

		err = CheckThresholds(newData(0), boundaryVoters, boundary)
		assert.NoError(t, err)
	})

	// the policy threshold may sit below half the total weight; a clamp to half would reject this
	t.Run("succeeds below half the total weight when the policy threshold is lower", func(t *testing.T) {
		low, lowVoters := newPolicy(t, []uint16{40, 30, 30}, 35)

		err := CheckThresholds(newData(0), []common.Address{lowVoters[0]}, low)
		assert.NoError(t, err)
	})

	// a zero threshold no longer disables the weight check; only the bips path can reach one
	t.Run("zero computed threshold still requires data provider weight", func(t *testing.T) {
		tiny, _ := newPolicy(t, []uint16{1, 1}, 1)
		data := buildFDCData(t, fdcMinimumThresholdBIPS, cosigners[:1], 1)

		err := CheckThresholds(data, cosigners[:1], tiny)
		assert.EqualError(t, err, "data providers threshold not reached")
	})

	// the policy's threshold binds, not a recomputed share of total weight
	t.Run("fails when weight exceeds half but not the policy threshold", func(t *testing.T) {
		strictPolicy, strictVoters := newPolicy(t, []uint16{51, 49}, 60)

		err := CheckThresholds(newData(0), []common.Address{strictVoters[0]}, strictPolicy)
		assert.EqualError(t, err, "data providers threshold not reached")
	})

	t.Run("fails when signer is neither cosigner nor data provider", func(t *testing.T) {
		data := newData(0)
		external := common.HexToAddress("0x99")
		signers := []common.Address{voters[0], voters[1], external}

		err := CheckThresholds(data, signers, policy)
		assert.EqualError(t, err, "signed by an entity that is neither data provider nor cosigner")
	})

	t.Run("propagates fdc threshold validation", func(t *testing.T) {
		fdcData := buildFDCData(t, 4500, cosigners, 1)
		signers := []common.Address{voters[0], cosigners[0]}

		err := CheckThresholds(fdcData, signers, policy)
		assert.EqualError(t, err, "one threshold should be above 50%")
	})

	t.Run("succeeds when thresholds are met", func(t *testing.T) {
		data := newData(1)
		signers := []common.Address{voters[0], voters[1], cosigners[0]}

		err := CheckThresholds(data, signers, policy)
		assert.NoError(t, err)
	})

	// Restore requires the reward-epoch policy's threshold in data-provider
	// weight among signers — a filter by that provider set on top of the
	// cryptographic Shamir thresholds enforced at reconstruction.
	t.Run("restore requires the policy threshold in weight", func(t *testing.T) {
		data := &instruction.DataFixed{
			OPType:             op.Wallet.Hash(),
			OPCommand:          op.KeyDataProviderRestore.Hash(),
			Cosigners:          cosigners,
			CosignersThreshold: 1,
		}

		// weight 50 is below the policy threshold of 55
		err := CheckThresholds(data, []common.Address{voters[0], cosigners[0]}, policy)
		assert.EqualError(t, err, "data providers threshold not reached")

		// weight 80 of 100 passes
		err = CheckThresholds(data, []common.Address{voters[0], voters[1], cosigners[0]}, policy)
		assert.NoError(t, err)
	})
}

func newPolicy(t *testing.T, weights []uint16, threshold uint16) (*cpolicy.SigningPolicy, []common.Address) {
	t.Helper()

	addresses := make([]common.Address, len(weights))
	for i := range weights {
		addresses[i] = common.BigToAddress(big.NewInt(int64(i + 1)))
	}

	voterSet, err := voters.NewSet(addresses, weights, nil)
	require.NoError(t, err)

	return &cpolicy.SigningPolicy{Threshold: threshold, Voters: voterSet}, addresses
}

func buildFDCData(t *testing.T, threshold uint16, cosigners []common.Address, cosignersThreshold uint64) *instruction.DataFixed {
	t.Helper()

	req := fdc2.IFdc2HubFdc2AttestationRequest{
		Header: fdc2.IFdc2HubFdc2RequestHeader{
			AttestationType: [32]byte{},
			SourceId:        [32]byte{},
			ThresholdBIPS:   threshold,
		},
		RequestBody: []byte("body"),
	}

	originalMessage, err := fdc.EncodeRequest(req)
	require.NoError(t, err)

	return &instruction.DataFixed{
		OPType:             op.FDC2.Hash(),
		OPCommand:          op.Prove.Hash(),
		Cosigners:          cosigners,
		CosignersThreshold: cosignersThreshold,
		OriginalMessage:    originalMessage,
	}
}
