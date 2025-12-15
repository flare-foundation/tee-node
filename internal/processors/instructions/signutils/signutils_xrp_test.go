package signutils_test

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/flare-foundation/tee-node/internal/processors/instructions/signutils"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/wallets"

	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/random"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
	"github.com/stretchr/testify/require"
)

// signXRPLTestSetup provides common setup and helpers for XRP signing tests
type signXRPLTestSetup struct {
	testNode  *node.Node
	wStorage  *wallets.Storage
	teeID     common.Address
	walletID  common.Hash
	epochID   uint32
	processor signutils.Processor
}

func setupSignXRPLTest(t *testing.T) *signXRPLTestSetup {
	t.Helper()

	testNode, _, wStorage := testutils.Setup(t)

	return &signXRPLTestSetup{
		testNode:  testNode,
		wStorage:  wStorage,
		teeID:     testNode.TeeID(),
		walletID:  common.HexToHash("0xfeedface"),
		epochID:   1,
		processor: signutils.NewProcessor(testNode, wStorage),
	}
}

// createWallet stores a wallet with provided parameters in storage
func (s *signXRPLTestSetup) createWallet(t *testing.T, keyID uint64, keyType, algo common.Hash, cosigners []common.Address, cosignersThreshold uint64) *wallets.Wallet {
	t.Helper()

	sk, err := wallets.GenerateKey(algo)
	require.NoError(t, err)

	wal := &wallets.Wallet{
		WalletID:           s.walletID,
		KeyID:              keyID,
		PrivateKey:         sk,
		KeyType:            keyType,
		SigningAlgo:        algo,
		Restored:           false,
		AdminPublicKeys:    []*ecdsa.PublicKey{},
		AdminsThreshold:    0,
		Cosigners:          cosigners,
		CosignersThreshold: cosignersThreshold,
		SettingsVersion:    common.Hash{},
		Settings:           []byte{},
		Status:             &wallets.WalletStatus{Nonce: 0, StatusCode: 0},
	}

	s.wStorage.Lock()
	defer s.wStorage.Unlock()

	err = s.wStorage.Store(wal)
	require.NoError(t, err)
	return wal
}

// buildPaymentInstruction creates a payment.DataFixed using provided tee/key pairs and cosigner data
func (s *signXRPLTestSetup) buildPaymentInstruction(t *testing.T, teeKeyPairs []payment.TeeIdKeyIdPair, cosigners []common.Address, cosignerThreshold uint64) *instruction.DataFixed {
	t.Helper()

	msg := payment.ITeePaymentsPaymentInstructionMessage{
		WalletId:         s.walletID,
		TeeIdKeyIdPairs:  teeKeyPairs,
		SenderAddress:    "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
		RecipientAddress: "rrrrrrrrrrrrrrrrrrrrrhoLvTp",
		Amount:           big.NewInt(1000000000),
		Fee:              big.NewInt(1000),
		PaymentReference: [32]byte{},
		Nonce:            uint64(0),
		SubNonce:         uint64(0),
		BatchEndTs:       uint64(0),
	}

	enc, err := abi.Arguments{payment.MessageArguments[op.Pay]}.Pack(msg)
	require.NoError(t, err)

	instructionID, err := random.Hash()
	require.NoError(t, err)

	return &instruction.DataFixed{
		InstructionID:          instructionID,
		TeeID:                  s.teeID,
		RewardEpochID:          s.epochID,
		OPType:                 op.XRP.Hash(),
		OPCommand:              op.Pay.Hash(),
		OriginalMessage:        enc,
		AdditionalFixedMessage: nil,
		Cosigners:              cosigners,
		CosignersThreshold:     cosignerThreshold,
	}
}

// decodeSignersLength returns number of signers in the returned XRPL JSON tx
func decodeSignersLength(t *testing.T, jsonTx []byte) int {
	t.Helper()

	var tx map[string]any
	require.NoError(t, json.Unmarshal(jsonTx, &tx))
	signers, ok := tx["Signers"].([]any)
	if !ok {
		return 0
	}
	return len(signers)
}

// ============================ Tests ============================

// Basic XRP Payment Signing Success
func TestSignXRPLBasicSuccess(t *testing.T) {
	setup := setupSignXRPLTest(t)

	// Create one XRP wallet/key
	setup.createWallet(t, 1, wallets.XRPType, wallets.XRPAlgo, []common.Address{}, 0)

	instr := setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 1}}, nil, 0)

	jsonTx, status, err := setup.processor.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.NoError(t, err)
	require.Nil(t, status)
	require.NotEmpty(t, jsonTx)

	// At least one signature present
	require.GreaterOrEqual(t, decodeSignersLength(t, jsonTx), 1)
}

// Multi-Key Multisig Signing
func TestSignXRPLMultiKeyMultisig(t *testing.T) {
	setup := setupSignXRPLTest(t)

	// Two XRP keys for same wallet
	setup.createWallet(t, 1, wallets.XRPType, wallets.XRPAlgo, []common.Address{}, 0)
	setup.createWallet(t, 2, wallets.XRPType, wallets.XRPAlgo, []common.Address{}, 0)

	pairs := []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 1}, {TeeId: setup.teeID, KeyId: 2}}
	instr := setup.buildPaymentInstruction(t, pairs, nil, 0)

	jsonTx, _, err := setup.processor.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.NoError(t, err)
	require.Equal(t, 2, decodeSignersLength(t, jsonTx))
}

// Cosigner Validation and Threshold Enforcement
func TestSignXRPLCosignerValidationThreshold(t *testing.T) {
	setup := setupSignXRPLTest(t)

	// Wallet requires 2 cosigners (store cosigners on wallet)
	cos1Priv, _ := crypto.GenerateKey()
	cos2Priv, _ := crypto.GenerateKey()
	cos3Priv, _ := crypto.GenerateKey()
	wal := setup.createWallet(t, 1, wallets.XRPType, wallets.XRPAlgo, []common.Address{crypto.PubkeyToAddress(cos1Priv.PublicKey), crypto.PubkeyToAddress(cos2Priv.PublicKey), crypto.PubkeyToAddress(cos3Priv.PublicKey)}, 2)

	// Instruction with only 1 cosigner -> should fail
	instr := setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 1}}, wal.Cosigners[:1], 1)
	_, _, err := setup.processor.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "the number of provided cosigners does not match the number of saved cosigners")

	// Instruction with 3 cosigners, but threshold is 1 -> should fail
	instr = setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 1}}, wal.Cosigners, 1)
	_, _, err = setup.processor.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "the threshold of provided cosigners does not match the threshold of saved cosigners")

	// Instruction with 3 cosigners and threshold 2 -> should pass
	instrOK := setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 1}}, wal.Cosigners, 2)
	jsonTx, _, err := setup.processor.SignXRPLPayment(types.Threshold, instrOK, nil, nil, nil)
	require.NoError(t, err)
	require.GreaterOrEqual(t, decodeSignersLength(t, jsonTx), 1)
}

// Invalid Payment Instruction Parsing
func TestSignXRPLInvalidInstructionParsing(t *testing.T) {
	setup := setupSignXRPLTest(t)

	// Malformed original message
	instr := setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 1}}, nil, 0)
	instr.OriginalMessage = []byte{0x01, 0x02}

	_, _, err := setup.processor.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "abi: cannot marshal in to go type")
}

// Invalid Key Type Rejection and Invalid Signing Algorithm Rejection
func TestSignXRPLInvalidKeyTypeAlgoRejection(t *testing.T) {
	setup := setupSignXRPLTest(t)

	// EVM type with XRP algo -> should fail on key type
	setup.createWallet(t, 1, wallets.EVMType, wallets.XRPAlgo, []common.Address{}, 0)
	instr := setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 1}}, nil, 0)
	_, _, err := setup.processor.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "key type")

	// XRP type with EVM algo -> should fail on signing algo
	setup = setupSignXRPLTest(t)
	setup.createWallet(t, 2, wallets.XRPType, wallets.EVMAlgo, []common.Address{}, 0)
	instr2 := setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 2}}, nil, 0)
	_, _, err = setup.processor.SignXRPLPayment(types.Threshold, instr2, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "algorithm")
}

// Wallet Not Found Error
func TestSignXRPLWalletNotFound(t *testing.T) {
	setup := setupSignXRPLTest(t)

	// Reference non-existent key
	instr := setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 999}}, nil, 0)
	_, _, err := setup.processor.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.Error(t, err)
	require.Equal(t, wallets.ErrWalletNonExistent, err)
}

// TEE ID Mismatch Handling
func TestSignXRPLTeeIDMismatchNoKeysForSigning(t *testing.T) {
	setup := setupSignXRPLTest(t)

	// Create a valid key for this wallet, but reference a different TEE in instruction pairs
	setup.createWallet(t, 1, wallets.XRPType, wallets.XRPAlgo, []common.Address{}, 0)
	otherTEE := common.HexToAddress("0x1234567890123456789012345678901234567890")
	instr := setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: otherTEE, KeyId: 1}}, nil, 0)

	_, _, err := setup.processor.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no keys for signing")
}

// * ============================================================================

// Invalid XRP Payment Parameters (hits xrpl.CheckNativePayment error)
func TestSignXRPLInvalidXRPParameters(t *testing.T) {
	setup := setupSignXRPLTest(t)

	setup.createWallet(t, 1, wallets.XRPType, wallets.XRPAlgo, []common.Address{}, 0)

	// Test with negative amount
	msg := payment.ITeePaymentsPaymentInstructionMessage{
		WalletId:         setup.walletID,
		TeeIdKeyIdPairs:  []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 1}},
		SenderAddress:    "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
		RecipientAddress: "rrrrrrrrrrrrrrrrrrrrrhoLvTp",
		Amount:           big.NewInt(0),
		Fee:              big.NewInt(10),
		PaymentReference: [32]byte{},
		Nonce:            uint64(0),
		SubNonce:         uint64(0),
		BatchEndTs:       uint64(0),
	}

	enc, err := abi.Arguments{payment.MessageArguments[op.Pay]}.Pack(msg)
	require.NoError(t, err)

	instructionID, err := random.Hash()
	require.NoError(t, err)

	instr := &instruction.DataFixed{
		InstructionID:          instructionID,
		TeeID:                  setup.teeID,
		RewardEpochID:          setup.epochID,
		OPType:                 op.XRP.Hash(),
		OPCommand:              op.Pay.Hash(),
		OriginalMessage:        enc,
		AdditionalFixedMessage: nil,
		Cosigners:              nil,
		CosignersThreshold:     0,
	}

	_, _, err = setup.processor.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "non positive integer for Amount")
	// Error should come from xrpl.CheckNativePayment

	msg.Fee.SetInt64(0)
	enc, err = abi.Arguments{payment.MessageArguments[op.Pay]}.Pack(msg)
	require.NoError(t, err)

	instr.OriginalMessage = enc
	_, _, err = setup.processor.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "zero Fee set")
}

// Invalid Private Key Conversion (hits crypto.ToECDSA error)
func TestSignXRPLInvalidPrivateKey(t *testing.T) {
	setup := setupSignXRPLTest(t)

	// Create wallet with corrupted private key
	wal := &wallets.Wallet{
		WalletID:           setup.walletID,
		KeyID:              1,
		PrivateKey:         []byte{0x01, 0x02, 0x03}, // Invalid private key (too short)
		KeyType:            wallets.XRPType,
		SigningAlgo:        wallets.XRPAlgo,
		Restored:           false,
		AdminPublicKeys:    []*ecdsa.PublicKey{},
		AdminsThreshold:    0,
		Cosigners:          []common.Address{},
		CosignersThreshold: 0,
		SettingsVersion:    common.Hash{},
		Settings:           []byte{},
		Status:             &wallets.WalletStatus{Nonce: 0, StatusCode: 0},
	}

	err := setup.wStorage.Store(wal)
	require.NoError(t, err)

	instr := setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 1}}, nil, 0)

	_, _, err = setup.processor.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.Error(t, err)
	// Error should come from crypto.ToECDSA conversion
}
