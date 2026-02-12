package testutils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
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
	"github.com/flare-foundation/go-flare-common/pkg/random"
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
	t.Helper()

	instructionID, err := random.Hash()
	require.NoError(t, err)

	require.Less(t, 0, len(adminPrivKeys))
	adminPubKeys := make([]wallet.PublicKey, 0, len(adminPrivKeys))
	for _, adminPrivKey := range adminPrivKeys {
		aPubKey := types.PubKeyToStruct(&adminPrivKey.PublicKey)
		adminPubKeys = append(adminPubKeys, wallet.PublicKey{
			X: aPubKey.X,
			Y: aPubKey.Y,
		})
	}

	cosignerPubKeys := make([]common.Address, 0, len(cosignerPrivKeys))
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
		InstructionID:          instructionID,
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

	walletExistenceProof, err := wallets.ExtractKeyExistence(walletProofBytes, iSndD.TeeID())
	require.NoError(t, err)

	require.NoError(t, err)

	return *walletExistenceProof
}

// BuildMockPaymentOriginalMessage constructs a payment instruction payload for
// use in tests.
func BuildMockPaymentOriginalMessage(
	t *testing.T,
	mockWallet common.Hash,
	teeID common.Address,
	keyID uint64,
	amount int64,
	sender, receiver string,
) []byte {
	t.Helper()

	originalMessage := payment.ITeePaymentsPaymentInstructionMessage{
		WalletId: mockWallet,
		TeeIdKeyIdPairs: []payment.TeeIdKeyIdPair{{
			TeeId: teeID,
			KeyId: keyID,
		}},
		SenderAddress:    sender,
		RecipientAddress: receiver,
		Amount:           big.NewInt(amount),
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
	t *testing.T,
	opType op.Type,
	opCommand op.Command,
	originalMessage []byte,
	privKeys []*ecdsa.PrivateKey,
	teeID common.Address,
	rewardEpochID uint32,
	additionalFixedMessageRaw any,
	variableMessages [][]byte,
	cosigners []common.Address,
	cosignersThreshold uint64,
	submissionTag types.SubmissionTag,
	timestamp uint64,
) *types.Action {
	t.Helper()

	instructionID, err := random.Hash()
	require.NoError(t, err)

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
		require.NoError(t, err)
	}

	instructionDataFixed := instruction.DataFixed{
		InstructionID:          instructionID,
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
	require.NoError(t, err)

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
			instructionData.AdditionalVariableMessage = variableMessages[i]
			additionalVariableMessages[i] = instructionData.AdditionalVariableMessage
		}
		signatures[i], err = sign(&instructionData, privKey)
		require.NoError(t, err)
	}

	timestamps := make([]uint64, len(signatures))
	for i := range timestamps {
		randInt, err := rand.Int(rand.Reader, big.NewInt(10000000))
		require.NoError(t, err)
		timestamps[i] = randInt.Uint64()
	}

	slices.Sort(timestamps)

	action := types.Action{
		Data: types.ActionData{
			ID:            instructionID,
			Type:          types.Instruction,
			Message:       instructionDataFixedEncoded,
			SubmissionTag: submissionTag,
		},
		AdditionalVariableMessages: additionalVariableMessages,
		Timestamps:                 timestamps,
		AdditionalActionData:       nil,
		Signatures:                 signatures,
	}

	return &action
}

// BuildMockDirectAction fabricates a direct action with a random ID for tests.
func BuildMockDirectAction(t *testing.T, opType op.Type, opCommand op.Command, messageRaw any) *types.Action {
	t.Helper()

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

	actionID, err := random.Hash()
	require.NoError(t, err)

	action := types.Action{
		Data: types.ActionData{
			SubmissionTag: types.Submit,
			ID:            actionID,
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

func MockSignServerResult(t *testing.T, signPort int, actionResponseChan chan *types.ActionResult) {
	t.Helper()

	router := http.NewServeMux()

	router.HandleFunc("POST /result", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var actionResponse types.ActionResult
		err = json.Unmarshal(body, &actionResponse)
		require.NoError(t, err)

		actionResponseChan <- &actionResponse
		err = r.Body.Close()
		require.NoError(t, err)
	})

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", signPort), router))
}
