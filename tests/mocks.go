package utils

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"tee-node/pkg/requests"
	"tee-node/pkg/service/instructionservice/walletsinstruction"
	"tee-node/pkg/utils"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/stretchr/testify/require"

	commonpayment "github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
)

// Todo: I want to extract some logic for generating mock policies, wallets, etc. into this file.

func BuildMockInstruction(OpType string, OpCommand string, OriginalMessage []byte, additionalFixedMessageRaw interface{}, privKey *ecdsa.PrivateKey, teeId common.Address, instructionId string, rewardEpochId uint32) (*instruction.Instruction, error) {
	AdditionalFixedMessage, err := json.Marshal(additionalFixedMessageRaw)
	if err != nil {
		return nil, err
	}

	instructionData := instruction.Data{
		DataFixed: instruction.DataFixed{
			InstructionID:          common.HexToHash(instructionId),
			TeeID:                  teeId,
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

func CreateMockWallet(t *testing.T, nodeId common.Address, walletId common.Hash, keyId uint64, rewardEpochId uint32, privKeys, adminPrivKeys, cosignerPrivKeys []*ecdsa.PrivateKey) {
	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

	adminPubKeys := make([]wallet.PublicKey, 0)
	if len(adminPrivKeys) > 0 {
		for _, adminPrivKey := range adminPrivKeys {
			adminPubKey := wallet.PublicKey{}
			copy(adminPubKey.X[:], adminPrivKey.PublicKey.X.Bytes())
			copy(adminPubKey.Y[:], adminPrivKey.PublicKey.Y.Bytes())
			adminPubKeys = append(adminPubKeys, adminPubKey)
		}
	} else {
		pubKey := wallet.PublicKey{}
		copy(pubKey.X[:], privKeys[0].PublicKey.X.Bytes())
		copy(pubKey.Y[:], privKeys[0].PublicKey.Y.Bytes())
		adminPubKeys = []wallet.PublicKey{pubKey}
	}

	cosignerPubKeys := make([]common.Address, 0)
	for _, cosignerPrivKey := range cosignerPrivKeys {
		cosignerAddress := crypto.PubkeyToAddress(cosignerPrivKey.PublicKey)
		cosignerPubKeys = append(cosignerPubKeys, cosignerAddress)
	}

	request := wallet.ITeeWalletKeyManagerKeyGenerate{
		TeeId:              common.HexToAddress("1234"),
		WalletId:           walletId,
		KeyId:              keyId,
		OpType:             utils.StringToOpHash("WALLET"),
		OpTypeConstants:    make([]byte, 0),
		AdminsPublicKeys:   adminPubKeys,
		AdminsThreshold:    uint64(len(adminPubKeys)),
		Cosigners:          cosignerPubKeys,
		CosignersThreshold: uint64(len(cosignerPubKeys)),
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

	err = walletsinstruction.NewWallet(&instruction.Data.DataFixed)

	require.NoError(t, err)
}

func BuildMockPaymentOriginalMessage(t *testing.T, mockWallet string) []byte {
	originalMessage := commonpayment.ITeePaymentsPaymentInstructionMessage{
		WalletId:           common.HexToHash(mockWallet),
		SenderAddress:      "0x123",
		RecipientAddress:   "0x456",
		Amount:             big.NewInt(1000000000),
		PaymentReference:   [32]byte{},
		Nonce:              uint64(0),
		SubNonce:           uint64(0),
		MaxFee:             big.NewInt(0),
		MaxFeeTolerancePPM: uint32(0),
		BatchEndTs:         uint64(0),
	}

	originalMessageEncoded, err := abi.Arguments{commonpayment.MessageArguments[commonpayment.Pay]}.Pack(originalMessage)
	require.NoError(t, err)
	return originalMessageEncoded
}
