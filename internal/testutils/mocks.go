package testutils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/flare-foundation/tee-node/internal/processor/instructions/walletutils"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/constants"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/verification"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/stretchr/testify/require"
)

func CreateMockWallet(
	t *testing.T,
	nodeId common.Address,
	walletId common.Hash,
	keyId uint64,
	rewardEpochId uint32,
	adminPrivKeys, cosignerPrivKeys []*ecdsa.PrivateKey,
) wallet.ITeeWalletKeyManagerKeyExistence {
	instructionIdBytes, _ := GenerateRandomBytes(32)

	require.Less(t, 0, len(adminPrivKeys))
	adminPubKeys := make([]wallet.PublicKey, 0)
	for _, adminPrivKey := range adminPrivKeys {
		adminPubKey := types.PubKeyToStruct(&adminPrivKey.PublicKey)
		adminPubKeys = append(adminPubKeys, wallet.PublicKey(adminPubKey))
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
	encoded, err := abi.Arguments{wallet.MessageArguments[constants.KeyGenerate]}.Pack(request)
	require.NoError(t, err)

	instructionDataFixed := instruction.DataFixed{
		InstructionId:          common.BytesToHash(instructionIdBytes),
		TeeId:                  nodeId,
		RewardEpochId:          rewardEpochId,
		OpType:                 utils.StringToOpHash("WALLET"),
		OpCommand:              utils.StringToOpHash("KEY_GENERATE"),
		OriginalMessage:        encoded,
		AdditionalFixedMessage: nil,
	}
	require.NoError(t, err)

	walletProofBytes, err := walletutils.NewWallet(&instructionDataFixed)
	require.NoError(t, err)
	walletExistenceProof, err := structs.Decode[wallet.ITeeWalletKeyManagerKeyExistence](wallet.KeyExistenceStructArg, walletProofBytes)

	require.NoError(t, err)

	return walletExistenceProof
}

func BuildMockPaymentOriginalMessage(t *testing.T, mockWallet common.Hash) []byte {
	originalMessage := payment.ITeePaymentsPaymentInstructionMessage{
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

	originalMessageEncoded, err := abi.Arguments{payment.MessageArguments[constants.Pay]}.Pack(originalMessage)
	require.NoError(t, err)
	return originalMessageEncoded
}

func BuildMockQueuedActionInstruction(opType string, opCommand string, originalMessage []byte,
	privKeys []*ecdsa.PrivateKey, teeId common.Address, rewardEpochId uint32,
	additionalFixedMessageRaw interface{}, variableMessages []interface{},
	submissionTag types.SubmissionTag, timestamp uint64,
) (*types.Action, error) {
	instructionId, err := GenerateRandomBytes(32)
	if err != nil {
		return nil, err
	}
	var additionalFixedMessage []byte
	switch additionalFixedMessageRaw := additionalFixedMessageRaw.(type) {
	case []byte:
		additionalFixedMessage = additionalFixedMessageRaw
	case hexutil.Bytes:
		additionalFixedMessage = additionalFixedMessageRaw[:]
	case common.Hash:
		additionalFixedMessage = additionalFixedMessageRaw[:]
	default:
		additionalFixedMessage, err = json.Marshal(additionalFixedMessageRaw)
		if err != nil {
			return nil, err
		}
	}

	instructionDataFixed := instruction.DataFixed{
		InstructionId:          common.BytesToHash(instructionId),
		TeeId:                  teeId,
		RewardEpochId:          rewardEpochId,
		OpType:                 utils.StringToOpHash(opType),
		OpCommand:              utils.StringToOpHash(opCommand),
		OriginalMessage:        originalMessage,
		AdditionalFixedMessage: additionalFixedMessage,
		Timestamp:              timestamp,
	}
	instructionDataFixedEncoded, err := json.Marshal(instructionDataFixed)
	if err != nil {
		return nil, err
	}

	signatures := make([]hexutil.Bytes, len(privKeys))
	var additionalVariableMessages []hexutil.Bytes
	if len(variableMessages) != 0 {
		additionalVariableMessages = make([]hexutil.Bytes, len(privKeys))
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
		signatures[i], err = sign(&instructionData, privKey)
		if err != nil {
			return nil, err
		}
	}

	timestamps := make([]uint64, len(signatures))
	for i := range timestamps {
		randInt, err := rand.Int(rand.Reader, big.NewInt(10000000))
		if err != nil {
			return nil, err
		}
		timestamps[i] = randInt.Uint64()
	}

	action := types.Action{
		Data: types.ActionData{
			ID:            common.BytesToHash(instructionId),
			Type:          types.Instruction,
			Message:       instructionDataFixedEncoded,
			SubmissionTag: submissionTag,
		},
		AdditionalVariableMessages: additionalVariableMessages,
		Timestamps:                 timestamps,
		AdditionalActionData:       nil,
		Signatures:                 signatures,
	}

	return &action, nil
}

func BuildMockQueuedAction(t *testing.T, opType string, opCommand string, messageRaw any) *types.Action {
	var message []byte
	var err error
	switch messageRaw := messageRaw.(type) {
	case *verification.ITeeVerificationTeeAttestation:
		message, err = types.EncodeTeeAttestationRequest(messageRaw)
	default:
		message, err = json.Marshal(messageRaw)
	}
	require.NoError(t, err)

	di := types.DirectInstruction{
		OPType:    utils.StringToOpHash(opType),
		OPCommand: utils.StringToOpHash(opCommand),
		Message:   message,
	}
	enc, err := json.Marshal(di)
	require.NoError(t, err)

	actionId, err := GenerateRandomBytes(32)
	require.NoError(t, err)

	action := types.Action{
		Data: types.ActionData{
			SubmissionTag: types.Submit,
			ID:            common.BytesToHash(actionId),
			Type:          types.Direct,
			Message:       enc,
		},
	}

	return &action
}

func sign(r *instruction.Data, privKey *ecdsa.PrivateKey) ([]byte, error) {
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
