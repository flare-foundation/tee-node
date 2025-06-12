package testutils

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"tee-node/api/types"
	"tee-node/pkg/tee/processor/instructions/walletsinstruction"
	"tee-node/pkg/tee/utils"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/stretchr/testify/require"

	commonpayment "github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
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
	nonceBytes, _ := GenerateRandomBytes(32)

	sig, err := Sign(&instructionData, privKey)
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

func CreateMockWallet(t *testing.T, nodeId common.Address, walletId common.Hash, keyId uint64, rewardEpochId uint32, privKey *ecdsa.PrivateKey, adminPrivKeys, cosignerPrivKeys []*ecdsa.PrivateKey) {
	instructionIdBytes, _ := GenerateRandomBytes(32)

	adminPubKeys := make([]wallet.PublicKey, 0)
	if len(adminPrivKeys) > 0 {
		for _, adminPrivKey := range adminPrivKeys {
			adminPubKey := types.PubKeyToStruct(&adminPrivKey.PublicKey)
			adminPubKeys = append(adminPubKeys, wallet.PublicKey(adminPubKey))
		}
	} else {
		pubKey := types.PubKeyToStruct(&privKey.PublicKey)
		adminPubKeys = []wallet.PublicKey{wallet.PublicKey(pubKey)}
	}

	cosignerPubKeys := make([]common.Address, 0)
	for _, cosignerPrivKey := range cosignerPrivKeys {
		cosignerAddress := crypto.PubkeyToAddress(cosignerPrivKey.PublicKey)
		cosignerPubKeys = append(cosignerPubKeys, cosignerAddress)
	}

	request := wallet.ITeeWalletKeyManagerKeyGenerate{
		TeeId:    nodeId,
		WalletId: walletId,
		KeyId:    keyId,
		OpType:   utils.StringToOpHash("WALLET"),
		ConfigConstants: wallet.ITeeWalletKeyManagerKeyConfigConstants{
			OpTypeConstants:    make([]byte, 0),
			AdminsPublicKeys:   adminPubKeys,
			AdminsThreshold:    uint64(len(adminPubKeys)),
			Cosigners:          cosignerPubKeys,
			CosignersThreshold: uint64(len(cosignerPubKeys)),
		},
	}
	encoded, err := abi.Arguments{wallet.MessageArguments[wallet.KeyGenerate]}.Pack(request)
	require.NoError(t, err)

	instruction, err := BuildMockInstruction("WALLET",
		"KEY_GENERATE",
		encoded,
		interface{}(nil),
		privKey,
		nodeId,
		hex.EncodeToString(instructionIdBytes),
		rewardEpochId,
	)
	require.NoError(t, err)

	_, err = walletsinstruction.NewWallet(&instruction.Data.DataFixed)

	require.NoError(t, err)
}

func BuildMockPaymentOriginalMessage(t *testing.T, mockWallet common.Hash) []byte {
	originalMessage := commonpayment.ITeePaymentsPaymentInstructionMessage{
		WalletId:         mockWallet,
		SenderAddress:    "0x123",
		RecipientAddress: "0x456",
		Amount:           big.NewInt(1000000000),
		Fee:              big.NewInt(1000),
		PaymentReference: [32]byte{},
		Nonce:            uint64(0),
		SubNonce:         uint64(0),
		BatchEndTs:       uint64(0),
	}

	originalMessageEncoded, err := abi.Arguments{commonpayment.MessageArguments[commonpayment.Pay]}.Pack(originalMessage)
	require.NoError(t, err)
	return originalMessageEncoded
}

func BuildMockQueuedActionInstruction(opType string, opCommand string, originalMessage []byte,
	privKeys, cosignersPrivKeys []*ecdsa.PrivateKey, teeId common.Address, rewardEpochId uint32,
	additionalFixedMessageRaw interface{}, variableMessages, cosignersVariableMessages []interface{},
) (*types.QueuedAction, error) {
	instructionId, _ := GenerateRandomBytes(32)
	additionalFixedMessage, err := json.Marshal(additionalFixedMessageRaw)
	if err != nil {
		return nil, err
	}

	instructionDataFixed := instruction.DataFixed{
		InstructionID:          common.HexToHash(hex.EncodeToString(instructionId)),
		TeeID:                  teeId,
		RewardEpochID:          big.NewInt(int64(rewardEpochId)),
		OPType:                 utils.StringToOpHash(opType),
		OPCommand:              utils.StringToOpHash(opCommand),
		OriginalMessage:        originalMessage,
		AdditionalFixedMessage: additionalFixedMessage,
	}
	instructionDataFixedEncoded, err := json.Marshal(instructionDataFixed)
	if err != nil {
		return nil, err
	}

	signatures := make([][]byte, len(privKeys))
	var additionalVariableMessages [][]byte
	if len(variableMessages) != 0 {
		additionalVariableMessages = make([][]byte, len(privKeys))
	}

	for i, privKey := range privKeys {
		instructionData := instruction.Data{
			DataFixed:                 instructionDataFixed,
			AdditionalVariableMessage: []byte(""),
		}
		if len(variableMessages) != 0 {
			switch variableMessages[i].(type) {
			case []byte:
				instructionData.AdditionalVariableMessage = variableMessages[i].([]byte)
				additionalVariableMessages[i] = instructionData.AdditionalVariableMessage
			default:
				instructionData.AdditionalVariableMessage, err = json.Marshal(variableMessages[i])
				if err != nil {
					return nil, err
				}
				additionalVariableMessages[i] = instructionData.AdditionalVariableMessage
			}
		}
		signatures[i], err = Sign(&instructionData, privKey)
		if err != nil {
			return nil, err
		}
	}
	cosignerSignatures := make([][]byte, len(cosignersPrivKeys))
	var cosignerAdditionalVariableMessages [][]byte
	if len(variableMessages) != 0 {
		cosignerAdditionalVariableMessages = make([][]byte, len(cosignersPrivKeys))
	}

	for i, privKey := range cosignersPrivKeys {
		instructionData := instruction.Data{
			DataFixed:                 instructionDataFixed,
			AdditionalVariableMessage: []byte(""),
		}
		if len(variableMessages) != 0 {
			switch variableMessages[i].(type) {
			case []byte:
				instructionData.AdditionalVariableMessage = cosignersVariableMessages[i].([]byte)
			default:
				instructionData.AdditionalVariableMessage, err = json.Marshal(cosignersVariableMessages[i])
				if err != nil {
					return nil, err
				}
			}
			cosignerAdditionalVariableMessages[i] = instructionData.AdditionalVariableMessage
		}
		cosignerSignatures[i], err = Sign(&instructionData, privKey)
		if err != nil {
			return nil, err
		}
	}

	action := types.QueuedAction{
		Data: types.QueueActionData{
			Type:    types.InstructionType,
			Message: instructionDataFixedEncoded,
		},
		Signatures:                         signatures,
		AdditionalVariableMessages:         additionalVariableMessages,
		CosignerSignatures:                 cosignerSignatures,
		CosignerAdditionalVariableMessages: cosignerAdditionalVariableMessages,
	}

	return &action, nil
}

func BuildMockQueuedActionAction(opType string, opCommand string, messageRaw interface{}) (*types.QueuedAction, error) {
	message, err := json.Marshal(messageRaw)
	if err != nil {
		return nil, err
	}

	getData := types.ActionData{
		OPType:    utils.StringToOpHash(opType),
		OPCommand: utils.StringToOpHash(opCommand),
		Message:   message,
	}
	getDataEncoded, err := json.Marshal(getData)
	if err != nil {
		return nil, err
	}

	action := types.QueuedAction{
		Data: types.QueueActionData{
			Type:    types.ActionType,
			Message: getDataEncoded,
		},
	}

	return &action, nil
}

func Sign(r *instruction.Data, privKey *ecdsa.PrivateKey) ([]byte, error) {
	hash, err := r.HashForSigning()
	if err != nil {
		return nil, err
	}
	signature, err := utils.Sign(hash[:], privKey)
	if err != nil {
		return nil, err
	}

	return signature, nil
}
