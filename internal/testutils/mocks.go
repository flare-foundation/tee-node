package testutils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"slices"
	"testing"

	"github.com/flare-foundation/tee-node/internal/processors/instructions/walletutils"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/policy"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
	"github.com/flare-foundation/tee-node/pkg/wallets"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/verification"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/stretchr/testify/require"
)

// CreateMockWallet provisions a wallet in storage via the key generate
// instruction and returns its existence proof, for tests purposes.
func CreateMockWallet(
	t *testing.T,
	iSndD node.IdentifierSignerAndDecrypter,
	ps *policy.Storage,
	ws *wallets.Storage,
	walletID common.Hash,
	keyID uint64,
	rewardEpochID uint32,
	adminPrivKeys, cosignerPrivKeys []*ecdsa.PrivateKey,
) wallet.ITeeWalletKeyManagerKeyExistence {
	instructionIdBytes, _ := GenerateRandomBytes(32)

	require.Less(t, 0, len(adminPrivKeys))
	adminPubKeys := make([]wallet.PublicKey, 0)
	for _, adminPrivKey := range adminPrivKeys {
		aPubKey := types.PubKeyToStruct(&adminPrivKey.PublicKey)
		adminPubKeys = append(adminPubKeys, wallet.PublicKey{
			X: aPubKey.X,
			Y: aPubKey.Y,
		})
	}

	cosignerPubKeys := make([]common.Address, 0)
	for _, cosignerPrivKey := range cosignerPrivKeys {
		cosignerAddress := crypto.PubkeyToAddress(cosignerPrivKey.PublicKey)
		cosignerPubKeys = append(cosignerPubKeys, cosignerAddress)
	}

	request := wallet.ITeeWalletKeyManagerKeyGenerate{
		TeeId:       iSndD.TeeID(),
		WalletId:    walletID,
		KeyId:       keyID,
		KeyType:     wallets.XRPType,
		SigningAlgo: wallets.XRPAlgo,
		ConfigConstants: wallet.ITeeWalletKeyManagerKeyConfigConstants{
			AdminsPublicKeys:   adminPubKeys,
			AdminsThreshold:    uint64(len(adminPubKeys)),
			Cosigners:          cosignerPubKeys,
			CosignersThreshold: uint64(len(cosignerPubKeys)),
		},
	}
	encoded, err := abi.Arguments{wallet.MessageArguments[op.KeyGenerate]}.Pack(request)
	require.NoError(t, err)

	instructionDataFixed := instruction.DataFixed{
		InstructionID:          common.BytesToHash(instructionIdBytes),
		TeeID:                  iSndD.TeeID(),
		RewardEpochID:          rewardEpochID,
		OPType:                 op.Wallet.Hash(),
		OPCommand:              op.KeyGenerate.Hash(),
		OriginalMessage:        encoded,
		AdditionalFixedMessage: nil,
	}
	require.NoError(t, err)

	proc := walletutils.NewProcessor(
		iSndD, ps, ws,
	)

	walletProofBytes, _, err := proc.KeyGenerate(types.Threshold, &instructionDataFixed, nil, nil, nil)
	require.NoError(t, err)

	walletExistenceProof, err := wallets.ExtractKeyExistence(walletProofBytes)
	require.NoError(t, err)

	require.NoError(t, err)

	return *walletExistenceProof
}

// BuildMockPaymentOriginalMessage constructs a payment instruction payload for
// use in tests.
func BuildMockPaymentOriginalMessage(t *testing.T, mockWallet common.Hash, teeID common.Address, keyID uint64) []byte {
	originalMessage := payment.ITeePaymentsPaymentInstructionMessage{
		WalletId: mockWallet,
		TeeIdKeyIdPairs: []payment.TeeIdKeyIdPair{{
			TeeId: teeID,
			KeyId: keyID,
		}},
		SenderAddress:    "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
		RecipientAddress: "rrrrrrrrrrrrrrrrrrrrrhoLvTp",
		Amount:           big.NewInt(1000000000),
		Fee:              big.NewInt(1000),
		PaymentReference: [32]byte{},
		Nonce:            uint64(0),
		SubNonce:         uint64(0),
		BatchEndTs:       uint64(0),
	}

	originalMessageEncoded, err := abi.Arguments{payment.MessageArguments[op.Pay]}.Pack(originalMessage)
	require.NoError(t, err)
	return originalMessageEncoded
}

// BuildMockInstructionAction assembles an instruction action with the provided
// signing keys and payload for use in tests.
func BuildMockInstructionAction(
	opType op.Type,
	opCommand op.Command,
	originalMessage []byte,
	privKeys []*ecdsa.PrivateKey,
	teeID common.Address,
	rewardEpochID uint32,
	additionalFixedMessageRaw any,
	variableMessages []any,
	cosigners []common.Address,
	cosignersThreshold uint64,
	submissionTag types.SubmissionTag,
	timestamp uint64,
) (*types.Action, error) {
	instructionId, err := GenerateRandomBytes(32)
	if err != nil {
		return nil, err
	}
	var additionalFixedMessage []byte
	switch additionalFixedMessageRaw := additionalFixedMessageRaw.(type) {
	case nil:
		additionalFixedMessage = []byte{}
	case []byte:
		additionalFixedMessage = additionalFixedMessageRaw
	case hexutil.Bytes:
		additionalFixedMessage = additionalFixedMessageRaw
	case common.Hash:
		additionalFixedMessage = additionalFixedMessageRaw[:]
	default:
		additionalFixedMessage, err = json.Marshal(additionalFixedMessageRaw)
		if err != nil {
			return nil, err
		}
	}

	instructionDataFixed := instruction.DataFixed{
		InstructionID:          common.BytesToHash(instructionId),
		TeeID:                  teeID,
		RewardEpochID:          rewardEpochID,
		OPType:                 opType.Hash(),
		OPCommand:              opCommand.Hash(),
		OriginalMessage:        originalMessage,
		AdditionalFixedMessage: additionalFixedMessage,
		Timestamp:              timestamp,
		Cosigners:              cosigners,
		CosignersThreshold:     cosignersThreshold,
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
			switch msg := variableMessages[i].(type) {
			case []byte:
				instructionData.AdditionalVariableMessage = msg
				additionalVariableMessages[i] = instructionData.AdditionalVariableMessage
			default:
				instructionData.AdditionalVariableMessage, err = json.Marshal(msg)
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

	slices.Sort(timestamps)

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

// BuildMockDirectAction fabricates a direct action with a random ID for tests.
func BuildMockDirectAction(t *testing.T, opType op.Type, opCommand op.Command, messageRaw any) *types.Action {
	var message []byte
	var err error
	switch messageRaw := messageRaw.(type) {
	case *verification.ITeeVerificationTeeAttestation:
		message, err = types.EncodeTeeAttestationRequest(messageRaw)
	case nil:
		message = []byte{}
	default:
		message, err = json.Marshal(messageRaw)
	}
	require.NoError(t, err)

	di := types.DirectInstruction{
		OPType:    opType.Hash(),
		OPCommand: opCommand.Hash(),
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
