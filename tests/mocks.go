package utils

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"tee-node/pkg/requests"
	"tee-node/pkg/service/instructionservice/walletsservice"
	"tee-node/pkg/utils"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/stretchr/testify/require"

	commonpayment "github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
)

// Todo: I want to extract some logic for generating mock policies, wallets, etc. into this file.

func BuildMockInstruction(OpType string, OpCommand string, OriginalMessage []byte, additionalFixedMessageRaw interface{}, privKey *ecdsa.PrivateKey, teeId string, instructionId string, rewardEpochId uint32) (*instruction.Instruction, error) {
	AdditionalFixedMessage, err := json.Marshal(additionalFixedMessageRaw)
	if err != nil {
		return nil, err
	}

	instructionData := instruction.Data{
		DataFixed: instruction.DataFixed{
			InstructionID:          common.HexToHash(instructionId),
			TeeID:                  common.HexToAddress(teeId),
			RewardEpochID:          big.NewInt(int64(rewardEpochId)),
			OPType:                 utils.StringToOpHash(OpType),
			OPCommand:              utils.StringToOpHash(OpCommand),
			OriginalMessage:        OriginalMessage,
			AdditionalFixedMessage: AdditionalFixedMessage,
		},
		AdditionalVariableMessage: []byte(""),
	}
	nonceBytes, _ := utils.GenerateRandomBytes(32)

	sig, err := requests.Sign(&instructionData, privKey)
	if err != nil {
		fmt.Printf("Error signing instruction: %v\n", err)
		return nil, err
	}

	return &instruction.Instruction{
		Challenge: common.BytesToHash(nonceBytes),
		Data:      instructionData,
		Signature: sig,
	}, nil

}

func CreateMockWallet(t *testing.T, nodeId string, walletId string, keyId string, privKeys []*ecdsa.PrivateKey, rewardEpochId uint32) {
	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

	keyIdBig, err := strconv.ParseUint(keyId, 10, 32)
	require.NoError(t, err)

	request := wallet.ITeeWalletManagerKeyGenerate{
		TeeId:    common.HexToAddress("1234"),
		WalletId: common.HexToHash(walletId),
		KeyId:    big.NewInt(int64(keyIdBig)),
		OpType:   utils.StringToOpHash("WALLET"),
	}
	encoded, err := abi.Arguments{wallet.MessageArguments[wallet.KeyGenerate]}.Pack(request)
	require.NoError(t, err)

	instruction, err := BuildMockInstruction("WALLET",
		"KEY_GENERATE",
		encoded,
		interface{}(nil),
		privKeys[0],
		nodeId,
		hex.EncodeToString(instructionIdBytes),
		rewardEpochId,
	)
	require.NoError(t, err)

	err = walletsservice.NewWallet(&instruction.Data.DataFixed)

	require.NoError(t, err)

}

func BuildMockPaymentOriginalMessage(t *testing.T, mockWallet string) []byte {
	originalMessage := commonpayment.ITeePaymentsPaymentInstructionMessage{
		WalletId:           common.HexToHash(mockWallet),
		SenderAddress:      "0x123",
		RecipientAddress:   "0x456",
		Amount:             big.NewInt(1000000000),
		PaymentReference:   [32]byte{},
		Nonce:              big.NewInt(0),
		SubNonce:           big.NewInt(0),
		MaxFee:             big.NewInt(0),
		MaxFeeTolerancePPM: big.NewInt(0),
		BatchEndTs:         big.NewInt(0),
	}

	originalMessageEncoded, err := abi.Arguments{commonpayment.MessageArguments[commonpayment.Pay]}.Pack(originalMessage)
	require.NoError(t, err)
	return originalMessageEncoded
}
