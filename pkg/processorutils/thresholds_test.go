package processorutils

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	cpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/connector"
	"github.com/flare-foundation/go-flare-common/pkg/voters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/flare-foundation/tee-node/pkg/fdc"
)

func TestComputeThreshold(t *testing.T) {
	// exact division
	assert.Equal(t, uint16(50), computeThreshold(100, maxBIPS/2))
	// rounds up on remainder
	assert.Equal(t, uint16(2), computeThreshold(3, maxBIPS/2))
	// zero bips
	assert.Equal(t, uint16(0), computeThreshold(42, 0))
}

func TestDataProvidersThreshold(t *testing.T) {
	totalWeight := uint16(100)
	cosigners := []common.Address{
		common.HexToAddress("0x15"),
		common.HexToAddress("0x16"),
		common.HexToAddress("0x17"),
		common.HexToAddress("0x18"),
	}

	t.Run("wallet restore has zero threshold", func(t *testing.T) {
		data := &instruction.DataFixed{
			OPType:    op.Wallet.Hash(),
			OPCommand: op.KeyDataProviderRestore.Hash(),
		}

		threshold, err := dataProvidersThreshold(data, totalWeight)
		assert.NoError(t, err)
		assert.Equal(t, uint16(0), threshold)
	})

	t.Run("op different from Wallet/KeyDataProviderRestore/F_FDC2/Prove should have threshold = computeThreshold(totalWeight, maxBIPS/2)", func(t *testing.T) {
		data := &instruction.DataFixed{
			OPType:    op.XRP.Hash(),
			OPCommand: op.Pay.Hash(),
		}

		threshold, err := dataProvidersThreshold(data, totalWeight)
		assert.NoError(t, err)
		assert.Equal(t, computeThreshold(totalWeight, maxBIPS/2), threshold)
	})

	t.Run("FDC request with invalid message should fail", func(t *testing.T) {
		data := &instruction.DataFixed{
			OPType:          op.FDC2.Hash(),
			OPCommand:       op.Prove.Hash(),
			OriginalMessage: []byte("invalid"),
		}

		threshold, err := dataProvidersThreshold(data, totalWeight)
		assert.Error(t, err)
		assert.Equal(t, uint16(0), threshold)
	})

	t.Run("FDC message with zero threshold should fall back to computeThreshold(totalWeight, maxBIPS/2)", func(t *testing.T) {
		data := buildFDCData(t, 0, nil, 0)

		threshold, err := dataProvidersThreshold(data, totalWeight)
		assert.NoError(t, err)
		assert.Equal(t, computeThreshold(totalWeight, maxBIPS/2), threshold)
	})

	t.Run("FDC request with threshold too low should fail", func(t *testing.T) {
		data := buildFDCData(t, fdcMinimumThresholdBIPS-1, nil, 0)

		_, err := dataProvidersThreshold(data, totalWeight)
		assert.EqualError(t, err, "data providers threshold too low")
	})

	t.Run("FDC request with cosigner threshold below 50% should fail", func(t *testing.T) {
		data := buildFDCData(t, maxBIPS/2-1, cosigners, 2)

		_, err := dataProvidersThreshold(data, totalWeight)
		assert.EqualError(t, err, "one threshold should be above 50%")
	})

	t.Run("FDC request with threshold too high should fail", func(t *testing.T) {
		data := buildFDCData(t, maxBIPS, nil, 0)

		_, err := dataProvidersThreshold(data, totalWeight)
		assert.EqualError(t, err, "data providers threshold too high")
	})

	t.Run("FDC valid threshold uses provided bips", func(t *testing.T) {
		data := buildFDCData(t, maxBIPS*0.6, cosigners[:2], 1)

		threshold, err := dataProvidersThreshold(data, totalWeight)
		assert.NoError(t, err)
		assert.Equal(t, computeThreshold(totalWeight, maxBIPS*0.6), threshold)
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
	policy, voters := newPolicy(weights)
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
		signers := []common.Address{voters[0]} // weight equals 50, threshold requires > 50

		err := CheckThresholds(data, signers, policy)
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
}

func newPolicy(weights []uint16) (*cpolicy.SigningPolicy, []common.Address) {
	addresses := make([]common.Address, len(weights))
	for i := range weights {
		addresses[i] = common.BigToAddress(big.NewInt(int64(i + 1)))
	}

	return &cpolicy.SigningPolicy{
		Voters: voters.NewSet(addresses, weights, nil),
	}, addresses
}

func buildFDCData(t *testing.T, threshold uint16, cosigners []common.Address, cosignersThreshold uint64) *instruction.DataFixed {
	t.Helper()

	req := connector.IFdc2HubFdc2AttestationRequest{
		Header: connector.IFdc2HubFdc2RequestHeader{
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
