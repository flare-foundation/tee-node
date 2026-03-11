package signutils_test

import (
	"crypto/ecdsa"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/flare-foundation/tee-node/internal/processors/instructions/signutils"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/wallets"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/random"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/signing"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/signing/secp256k1"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/signing/signer"
	"github.com/stretchr/testify/require"
)

var mockWalletID = common.HexToHash("0xabcdef")
var mockKeyID = uint64(1)

func TestSignPaymentTransaction(t *testing.T) {
	testNode, pStorage, wStorage := testutils.Setup(t)

	numVoters, randSeed, epochID := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(t, pStorage, numVoters, randSeed, epochID)

	testutils.CreateMockWallet(t, testNode, pStorage, wStorage, mockWalletID, mockKeyID, epochID, []*ecdsa.PrivateKey{privKeys[0]}, nil)

	instructionID, err := random.Hash()
	require.NoError(t, err)
	iDataFixed := instruction.DataFixed{
		InstructionID: instructionID,
		TeeID:         testNode.TeeID(),
		RewardEpochID: epochID,
		OPType:        op.XRP.Hash(),
		OPCommand:     op.Pay.Hash(),
		OriginalMessage: testutils.BuildMockPaymentOriginalMessage(
			t, mockWalletID, testNode.TeeID(), mockKeyID, 1000000000, 1000, []byte{0x27, 0x10, 0x00, 0x00}, "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", "rrrrrrrrrrrrrrrrrrrrrhoLvTp",
		),
		AdditionalFixedMessage: nil,
	}

	proc := signutils.NewProcessor(testNode, wStorage, nil)

	t.Run("sign XRP payment", func(t *testing.T) {
		_, _, err = proc.SignXRPLPayment(types.End, &iDataFixed, nil, nil, nil) // using types.End to skip posting to proxy
		require.NoError(t, err, "response")
	})

	// Nullification is triggered by a negative-BIPS fee schedule entry (0xFFFF).
	iDataFixed.OriginalMessage = testutils.BuildMockPaymentOriginalMessage(
		t, mockWalletID, testNode.TeeID(), mockKeyID, 0, 1000, []byte{0xFF, 0xFF, 0x00, 0x00}, "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
	)
	t.Run("nullify XRP payment", func(t *testing.T) {
		_, _, err = proc.SignXRPLPayment(types.End, &iDataFixed, nil, nil, nil) // using types.End to skip posting to proxy
		require.NoError(t, err, "response")
	})
}

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
		processor: signutils.NewProcessor(testNode, wStorage, nil),
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

// buildPaymentInstruction creates an instruction.DataFixed using provided tee/key pairs and cosigner data.
// If feeSchedule is nil, a single-entry 100%-of-MaxFee schedule with no delay is used.
func (s *signXRPLTestSetup) buildPaymentInstruction(t *testing.T, teeKeyPairs []payment.TeeIdKeyIdPair, cosigners []common.Address, cosignerThreshold uint64, feeSchedule []byte) *instruction.DataFixed {
	t.Helper()

	if feeSchedule == nil {
		feeSchedule = []byte{0x27, 0x10, 0x00, 0x00} // 100% of MaxFee, 0s delay
	}

	msg := payment.ITeePaymentsPaymentInstructionMessage{
		WalletId:         s.walletID,
		TeeIdKeyIdPairs:  teeKeyPairs,
		SenderAddress:    "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
		RecipientAddress: "rrrrrrrrrrrrrrrrrrrrrhoLvTp",
		Amount:           big.NewInt(1000000000),
		MaxFee:           big.NewInt(1000),
		FeeSchedule:      feeSchedule,
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

// startMockResultServer creates an httptest server that captures ActionResponse
// POSTs to /result and returns them on the channel. The server is cleaned up
// automatically when the test ends.
func startMockResultServer(t *testing.T) (*settings.ProxyURLMutex, <-chan *types.ActionResponse) {
	t.Helper()
	ch := make(chan *types.ActionResponse, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var resp types.ActionResponse
		require.NoError(t, json.NewDecoder(r.Body).Decode(&resp))
		ch <- &resp
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	proxyMux := &settings.ProxyURLMutex{}
	proxyMux.URL = srv.URL
	return proxyMux, ch
}

// signersCountFromResponse returns the number of signers in the last transaction
// of the goroutine-posted response (a JSON array of XRPL transactions).
func signersCountFromResponse(t *testing.T, resp *types.ActionResponse) int {
	t.Helper()
	var txs types.XRPSignResponse
	require.NoError(t, json.Unmarshal(resp.Result.Data, &txs))
	if len(txs) == 0 {
		return 0
	}
	signers, ok := txs[len(txs)-1]["Signers"].([]any)
	if !ok {
		return 0
	}
	return len(signers)
}

// requireValidSignatures asserts that every signer entry in every transaction
// carries a cryptographically valid XRPL multisig signature.
func requireValidSignatures(t *testing.T, txs types.XRPSignResponse) {
	t.Helper()
	for i, tx := range txs {
		signersAny, ok := tx["Signers"].([]any)
		require.True(t, ok, "tx[%d] must have a Signers field", i)
		require.NotEmpty(t, signersAny, "tx[%d] must have at least one signer", i)
		for j, signerAny := range signersAny {
			signerMap, ok := signerAny.(map[string]any)
			require.True(t, ok, "tx[%d] signer[%d] must be a map", i, j)
			s, err := signer.Parse(signerMap)
			require.NoError(t, err, "tx[%d] signer[%d] parse failed", i, j)
			valid, err := signing.ValidateMultiSig(tx, s)
			require.NoError(t, err, "tx[%d] signer[%d] validation error", i, j)
			require.True(t, valid, "tx[%d] signer[%d] has invalid signature", i, j)
		}
	}
}

// requireSignedByWallets asserts that every wallet's XRPL address appears as a
// signer in every transaction in txs.
func requireSignedByWallets(t *testing.T, txs types.XRPSignResponse, wals []*wallets.Wallet) {
	t.Helper()
	expectedAddrs := make([]string, len(wals))
	for i, wal := range wals {
		prv := wallets.ToECDSAUnsafe(wal.PrivateKey)
		expectedAddrs[i] = secp256k1.PrvToAddress(prv)
	}
	for i, tx := range txs {
		signersAny, ok := tx["Signers"].([]any)
		require.True(t, ok, "tx[%d] must have a Signers field", i)
		found := make(map[string]bool)
		for _, signerAny := range signersAny {
			signerMap, ok := signerAny.(map[string]any)
			if !ok {
				continue
			}
			s, err := signer.Parse(signerMap)
			if err != nil {
				continue
			}
			found[s.Account] = true
		}
		for _, addr := range expectedAddrs {
			require.True(t, found[addr], "tx[%d]: expected signer %s not found in Signers", i, addr)
		}
	}
}

// Basic XRP Payment Signing Success
func TestSignXRPLBasicSuccess(t *testing.T) {
	setup := setupSignXRPLTest(t)
	wal := setup.createWallet(t, 1, wallets.XRPType, wallets.XRPAlgo, []common.Address{}, 0)

	proxyMux, responses := startMockResultServer(t)
	proc := signutils.NewProcessor(setup.testNode, setup.wStorage, proxyMux)
	instr := setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 1}}, nil, 0, nil)

	result, status, err := proc.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.NoError(t, err)
	require.Nil(t, status)
	require.Equal(t, []byte{}, result)

	select {
	case resp := <-responses:
		require.GreaterOrEqual(t, signersCountFromResponse(t, resp), 1)
		var txs types.XRPSignResponse
		require.NoError(t, json.Unmarshal(resp.Result.Data, &txs))
		requireValidSignatures(t, txs)
		requireSignedByWallets(t, txs, []*wallets.Wallet{wal})
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for goroutine to post signed transaction")
	}
}

// Multi-Key Multisig Signing
func TestSignXRPLMultiKeyMultisig(t *testing.T) {
	setup := setupSignXRPLTest(t)
	wal1 := setup.createWallet(t, 1, wallets.XRPType, wallets.XRPAlgo, []common.Address{}, 0)
	wal2 := setup.createWallet(t, 2, wallets.XRPType, wallets.XRPAlgo, []common.Address{}, 0)

	proxyMux, responses := startMockResultServer(t)
	proc := signutils.NewProcessor(setup.testNode, setup.wStorage, proxyMux)
	pairs := []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 1}, {TeeId: setup.teeID, KeyId: 2}}
	instr := setup.buildPaymentInstruction(t, pairs, nil, 0, nil)

	_, _, err := proc.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.NoError(t, err)

	select {
	case resp := <-responses:
		require.Equal(t, 2, signersCountFromResponse(t, resp))
		var txs types.XRPSignResponse
		require.NoError(t, json.Unmarshal(resp.Result.Data, &txs))
		requireValidSignatures(t, txs)
		requireSignedByWallets(t, txs, []*wallets.Wallet{wal1, wal2})
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for goroutine to post signed transaction")
	}
}

// Cosigner Validation and Threshold Enforcement
func TestSignXRPLCosignerValidationThreshold(t *testing.T) {
	setup := setupSignXRPLTest(t)

	cos1Priv, _ := crypto.GenerateKey()
	cos2Priv, _ := crypto.GenerateKey()
	cos3Priv, _ := crypto.GenerateKey()
	wal := setup.createWallet(t, 1, wallets.XRPType, wallets.XRPAlgo, []common.Address{crypto.PubkeyToAddress(cos1Priv.PublicKey), crypto.PubkeyToAddress(cos2Priv.PublicKey), crypto.PubkeyToAddress(cos3Priv.PublicKey)}, 2)

	// Instruction with only 1 cosigner -> should fail
	instr := setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 1}}, wal.Cosigners[:1], 1, nil)
	_, _, err := setup.processor.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "the number of provided cosigners does not match the number of saved cosigners")

	// Instruction with 3 cosigners, but threshold is 1 -> should fail
	instr = setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 1}}, wal.Cosigners, 1, nil)
	_, _, err = setup.processor.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "the threshold of provided cosigners does not match the threshold of saved cosigners")

	// Instruction with 3 cosigners and threshold 2 -> should pass
	proxyMux, responses := startMockResultServer(t)
	proc := signutils.NewProcessor(setup.testNode, setup.wStorage, proxyMux)
	instrOK := setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 1}}, wal.Cosigners, 2, nil)
	_, _, err = proc.SignXRPLPayment(types.Threshold, instrOK, nil, nil, nil)
	require.NoError(t, err)

	select {
	case resp := <-responses:
		require.GreaterOrEqual(t, signersCountFromResponse(t, resp), 1)
		var txs types.XRPSignResponse
		require.NoError(t, json.Unmarshal(resp.Result.Data, &txs))
		requireValidSignatures(t, txs)
		requireSignedByWallets(t, txs, []*wallets.Wallet{wal})
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for goroutine to post signed transaction")
	}
}

// Invalid Payment Instruction Parsing
func TestSignXRPLInvalidInstructionParsing(t *testing.T) {
	setup := setupSignXRPLTest(t)

	instr := setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 1}}, nil, 0, nil)
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
	instr := setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 1}}, nil, 0, nil)
	_, _, err := setup.processor.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "key type")

	// XRP type with EVM algo -> should fail on signing algo
	setup = setupSignXRPLTest(t)
	setup.createWallet(t, 2, wallets.XRPType, wallets.EVMAlgo, []common.Address{}, 0)
	instr2 := setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 2}}, nil, 0, nil)
	_, _, err = setup.processor.SignXRPLPayment(types.Threshold, instr2, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "algorithm")
}

// Wallet Not Found Error
func TestSignXRPLWalletNotFound(t *testing.T) {
	setup := setupSignXRPLTest(t)

	instr := setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 999}}, nil, 0, nil)
	_, _, err := setup.processor.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.Error(t, err)
	require.Equal(t, wallets.ErrWalletNonExistent, err)
}

// TEE ID Mismatch Handling
func TestSignXRPLTeeIDMismatchNoKeysForSigning(t *testing.T) {
	setup := setupSignXRPLTest(t)

	setup.createWallet(t, 1, wallets.XRPType, wallets.XRPAlgo, []common.Address{}, 0)
	otherTEE := common.HexToAddress("0x1234567890123456789012345678901234567890")
	instr := setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: otherTEE, KeyId: 1}}, nil, 0, nil)

	_, _, err := setup.processor.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no keys for signing")
}

// Invalid XRP Payment Parameters (hits xrpl.CheckNativePayment error)
func TestSignXRPLInvalidXRPParameters(t *testing.T) {
	setup := setupSignXRPLTest(t)
	setup.createWallet(t, 1, wallets.XRPType, wallets.XRPAlgo, []common.Address{}, 0)

	instr := setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 1}}, nil, 0, nil)

	instr.OriginalMessage = testutils.BuildMockPaymentOriginalMessage(
		t, setup.walletID, setup.teeID, 1, 0, 10, []byte{0x27, 0x10, 0x00, 0x00},
		"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", "rrrrrrrrrrrrrrrrrrrrrhoLvTp",
	)
	_, _, err := setup.processor.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "non positive integer for Amount")

	instr.OriginalMessage = testutils.BuildMockPaymentOriginalMessage(
		t, setup.walletID, setup.teeID, 1, 0, 0, []byte{0x27, 0x10, 0x00, 0x00},
		"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", "rrrrrrrrrrrrrrrrrrrrrhoLvTp",
	)
	_, _, err = setup.processor.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "zero Fee set")
}

// TestSignXRPLMultiEntryScheduleWithDelay verifies that a fee schedule with
// multiple entries causes the goroutine to post an intermediate result followed
// by a final result after the scheduled delay.
func TestSignXRPLMultiEntryScheduleWithDelay(t *testing.T) {
	setup := setupSignXRPLTest(t)
	wal := setup.createWallet(t, 1, wallets.XRPType, wallets.XRPAlgo, []common.Address{}, 0)

	proxyMux, responses := startMockResultServer(t)
	proc := signutils.NewProcessor(setup.testNode, setup.wStorage, proxyMux)

	// Two-entry fee schedule:
	//   Entry 0: 50% of MaxFee (5000 BIPS = 0x1388), 0s delay  → posted immediately
	//   Entry 1: 100% of MaxFee (10000 BIPS = 0x2710), 1s delay → posted after 1s
	feeSchedule := []byte{0x13, 0x88, 0x00, 0x00, 0x27, 0x10, 0x00, 0x01}

	instr := setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 1}}, nil, 0, feeSchedule)

	start := time.Now()
	result, status, err := proc.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.NoError(t, err)
	require.Nil(t, status)
	require.Equal(t, []byte{}, result)

	// First response: intermediate (status=3), arrives immediately (0s delay on entry 0).
	var firstResp *types.ActionResponse
	select {
	case firstResp = <-responses:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for first (intermediate) response")
	}
	require.Equal(t, uint8(3), firstResp.Result.Status)
	var firstTxs types.XRPSignResponse
	require.NoError(t, json.Unmarshal(firstResp.Result.Data, &firstTxs))
	require.Len(t, firstTxs, 1, "first response must contain exactly 1 transaction")
	requireValidSignatures(t, firstTxs)
	requireSignedByWallets(t, firstTxs, []*wallets.Wallet{wal})

	// Second response: final (status=1), arrives after the 1s delay on entry 1.
	var secondResp *types.ActionResponse
	select {
	case secondResp = <-responses:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for second (final) response")
	}
	require.GreaterOrEqual(t, time.Since(start), time.Second, "second response must not arrive before the 1s delay")
	require.Equal(t, uint8(1), secondResp.Result.Status)
	var secondTxs types.XRPSignResponse
	require.NoError(t, json.Unmarshal(secondResp.Result.Data, &secondTxs))
	require.Len(t, secondTxs, 2, "second response must contain 2 transactions (cumulative)")
	requireValidSignatures(t, secondTxs)
	requireSignedByWallets(t, secondTxs, []*wallets.Wallet{wal})
}

// Invalid Private Key Conversion (hits crypto.ToECDSA error)
func TestSignXRPLInvalidPrivateKey(t *testing.T) {
	setup := setupSignXRPLTest(t)

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

	instr := setup.buildPaymentInstruction(t, []payment.TeeIdKeyIdPair{{TeeId: setup.teeID, KeyId: 1}}, nil, 0, nil)

	_, _, err = setup.processor.SignXRPLPayment(types.Threshold, instr, nil, nil, nil)
	require.Error(t, err)
}
