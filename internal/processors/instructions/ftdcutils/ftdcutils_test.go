package ftdcutils

import (
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/connector"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/ftdc"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/stretchr/testify/require"
)

func TestAbiDecodeFTDCAttestationResponse(t *testing.T) {
	testNode, pStorage, _ := testutils.Setup(t)

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	policy, signers, privKeys, err := testutils.GenerateAndSetInitialPolicy(pStorage, numVoters, randSeed, epochId)
	require.NoError(t, err)

	requestHeader := connector.IFtdcHubFtdcRequestHeader{
		AttestationType: [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		SourceId:        [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		ThresholdBIPS:   100,
	}

	requestBody := []byte{1, 2, 3, 4, 5}
	responseBody := []byte{6, 7, 8, 9, 10}

	originalMessage := connector.IFtdcHubFtdcAttestationRequest{
		Header:      requestHeader,
		RequestBody: requestBody,
	}

	originalMessageEncoded, err := ftdc.EncodeRequest(originalMessage)
	require.NoError(t, err)

	timestamp := uint64(1234567890)

	instructionData := instruction.DataFixed{
		InstructionID: common.HexToHash("0x123"),
		TeeID:         common.HexToAddress("0x123"),
		RewardEpochID: 1,
		OPType:        op.FTDC.Hash(),
		OPCommand:     op.Prove.Hash(),
		//
		OriginalMessage:        originalMessageEncoded,
		AdditionalFixedMessage: responseBody,
		Timestamp:              timestamp,
		Cosigners:              signers[:2],
		CosignersThreshold:     1,
	}

	msgHash, _, _, err := ftdc.HashMessage(originalMessage, responseBody, signers[:2], 1, timestamp)
	require.NoError(t, err)

	signatures := make([]hexutil.Bytes, 0, len(privKeys))
	dataProviderIndex := make(map[common.Address]int)
	for i, privKey := range privKeys {
		signature, err := utils.Sign(msgHash[:], privKey)
		require.NoError(t, err)
		signatures = append(signatures, signature)

		if i != 0 {
			dataProviderIndex[crypto.PubkeyToAddress(privKey.PublicKey)] = i
		}
	}

	proc := NewProcessor(testNode)

	res, _, err := proc.Prove(types.Threshold, &instructionData, signatures, signers, policy)
	require.NoError(t, err)

	var proveResponse ftdc.ProveResponse
	err = json.Unmarshal(res, &proveResponse)
	require.NoError(t, err)

	responseHeader, err := ftdc.DecodeResponse(proveResponse.ResponseHeader)
	require.NoError(t, err)

	require.Equal(t, responseHeader.AttestationType, originalMessage.Header.AttestationType)
	require.Equal(t, responseHeader.SourceId, originalMessage.Header.SourceId)
	require.Equal(t, responseHeader.ThresholdBIPS, originalMessage.Header.ThresholdBIPS)
	require.Equal(t, responseHeader.Cosigners, instructionData.Cosigners)
	require.Equal(t, responseHeader.CosignersThreshold, instructionData.CosignersThreshold)
	require.Equal(t, responseHeader.Timestamp, timestamp)
}
