package ftdcutils

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	commonpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/random"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/connector"
	"github.com/flare-foundation/tee-node/internal/processors/instructions"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/ftdc"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/policy"

	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/stretchr/testify/require"
)

// * ========================== FTDC PROVE TEST SETUP ========================== *

// ftdcProveTestSetup holds common test setup data for FTDC Prove tests
type ftdcProveTestSetup struct {
	testNode            *node.Node
	pStorage            *policy.Storage
	teeID               common.Address
	epochID             uint32
	policy              *commonpolicy.SigningPolicy
	signers             []common.Address
	privKeys            []*ecdsa.PrivateKey
	cosignerPrivKeys    []*ecdsa.PrivateKey
	cosigners           []common.Address
	processor           Processor
	defaultTimestamp    uint64
	defaultRequestBody  []byte
	defaultResponseBody []byte
}

// setupFTDCProveTest creates a standard test environment for FTDC Prove tests
func setupFTDCProveTest(t *testing.T) *ftdcProveTestSetup {
	t.Helper()

	testNode, pStorage, _ := testutils.Setup(t)

	numVoters, randSeed, epochID := 100, int64(12345), uint32(1)
	policy, signers, privKeys := testutils.GenerateAndSetInitialPolicy(t, pStorage, numVoters, randSeed, epochID)

	// Setup cosigners (use first 10 providers as cosigners for simplicity)
	numCosigners := 10
	cosignerPrivKeys := privKeys[:numCosigners]
	cosigners := signers[:numCosigners]

	return &ftdcProveTestSetup{
		testNode:            testNode,
		pStorage:            pStorage,
		teeID:               testNode.TeeID(),
		epochID:             epochID,
		policy:              policy,
		signers:             signers,
		privKeys:            privKeys,
		cosignerPrivKeys:    cosignerPrivKeys,
		cosigners:           cosigners,
		processor:           NewProcessor(testNode),
		defaultTimestamp:    uint64(1234567890),
		defaultRequestBody:  []byte{1, 2, 3, 4, 5},
		defaultResponseBody: []byte{6, 7, 8, 9, 10},
	}
}

func (s *ftdcProveTestSetup) setupInstructionProcessor() instructions.Processor {
	return instructions.NewProcessor(s.processor.Prove, s.testNode, s.pStorage, true)
}

// buildFTDCRequest creates an FTDC attestation request with the given parameters
func (s *ftdcProveTestSetup) buildFTDCRequest(attestationType, sourceID [32]byte, thresholdBIPS uint16, requestBody []byte) connector.IFtdcHubFtdcAttestationRequest {
	return connector.IFtdcHubFtdcAttestationRequest{
		Header: connector.IFtdcHubFtdcRequestHeader{
			AttestationType: attestationType,
			SourceId:        sourceID,
			ThresholdBIPS:   thresholdBIPS,
		},
		RequestBody: requestBody,
	}
}

// defaultFTDCRequest creates a valid FTDC request with default parameters
func (s *ftdcProveTestSetup) defaultFTDCRequest() connector.IFtdcHubFtdcAttestationRequest {
	return s.buildFTDCRequest(
		utils.ToHash("PMWMultisigAccountConfigured"),
		utils.ToHash("XRP"),
		0, // (will use default)
		s.defaultRequestBody,
	)
}

// buildInstruction creates an instruction.DataFixed for FTDC Prove with the given parameters
func (s *ftdcProveTestSetup) buildInstruction(t *testing.T, request connector.IFtdcHubFtdcAttestationRequest, responseBody []byte, cosigners []common.Address, cosignersThreshold uint64, timestamp uint64) *instruction.DataFixed {
	t.Helper()

	originalMessageEncoded, err := ftdc.EncodeRequest(request)
	require.NoError(t, err)

	instructionID, err := random.Hash()
	require.NoError(t, err)

	return &instruction.DataFixed{
		InstructionID:          instructionID,
		TeeID:                  s.teeID,
		RewardEpochID:          s.epochID,
		OPType:                 op.FTDC.Hash(),
		OPCommand:              op.Prove.Hash(),
		OriginalMessage:        originalMessageEncoded,
		AdditionalFixedMessage: responseBody,
		Timestamp:              timestamp,
		Cosigners:              cosigners,
		CosignersThreshold:     cosignersThreshold,
	}
}

// buildDefaultInstruction creates a default FTDC Prove instruction
func (s *ftdcProveTestSetup) buildDefaultInstruction(t *testing.T) *instruction.DataFixed {
	t.Helper()

	request := s.defaultFTDCRequest()
	return s.buildInstruction(t, request, s.defaultResponseBody, s.cosigners[:2], 1, s.defaultTimestamp)
}

// signMessage signs a message hash with the given private keys and returns signatures and signers
func (s *ftdcProveTestSetup) signMessage(t *testing.T, msgHash common.Hash, privKeys []*ecdsa.PrivateKey) ([]hexutil.Bytes, []common.Address) {
	t.Helper()

	signatures := make([]hexutil.Bytes, 0, len(privKeys))
	signers := make([]common.Address, 0, len(privKeys))

	for _, privKey := range privKeys {
		signature, err := utils.Sign(msgHash[:], privKey)
		require.NoError(t, err)
		signatures = append(signatures, signature)
		signers = append(signers, crypto.PubkeyToAddress(privKey.PublicKey))
	}

	return signatures, signers
}

// signFTDCMessage creates the FTDC message hash and signs it with the given private keys
func (s *ftdcProveTestSetup) signFTDCMessage(t *testing.T, request connector.IFtdcHubFtdcAttestationRequest, responseBody []byte, cosigners []common.Address, cosignersThreshold uint64, timestamp uint64, privKeys []*ecdsa.PrivateKey) ([]hexutil.Bytes, []common.Address) {
	t.Helper()

	msgHash, _, _, err := ftdc.HashMessage(request, responseBody, cosigners, cosignersThreshold, timestamp)
	require.NoError(t, err)

	return s.signMessage(t, msgHash, privKeys)
}

// buildActionWithPolicySigners creates an Action whose signatures are valid for
// the generic instruction preprocessing (sign hash from instruction.Data).
func (s *ftdcProveTestSetup) buildActionWithPolicySigners(
	t *testing.T,
	instr *instruction.DataFixed,
	request connector.IFtdcHubFtdcAttestationRequest,
	responseBody []byte,
	cosigners []common.Address,
	cosignersThreshold uint64,
	privKeys []*ecdsa.PrivateKey,
) *types.Action {
	t.Helper()

	// variable messages must match signatures length
	sigs := make([]hexutil.Bytes, 0, len(privKeys))
	vars := make([]hexutil.Bytes, 0, len(privKeys))

	// Compute FTDC hash once
	ftdcHash, _, _, err := ftdc.HashMessage(request, responseBody, cosigners, cosignersThreshold, instr.Timestamp)
	require.NoError(t, err)

	for _, pk := range privKeys {
		// FTDC signature by provider
		ftdcSig, err := utils.Sign(ftdcHash[:], pk)
		require.NoError(t, err)

		// Provider signature over instruction hash including variable message (the FTDC sig)
		data := instruction.Data{DataFixed: *instr, AdditionalVariableMessage: ftdcSig}
		h, err := data.HashForSigning()
		require.NoError(t, err)
		provSig, err := utils.Sign(h[:], pk)
		require.NoError(t, err)

		sigs = append(sigs, provSig)
		vars = append(vars, ftdcSig)
	}

	// Encode instruction.DataFixed to JSON as expected by processorutils.Parse
	encBytes, err := json.Marshal(instr)
	require.NoError(t, err)

	return &types.Action{
		Data: types.ActionData{
			ID:            instr.InstructionID,
			SubmissionTag: types.Threshold,
			Message:       encBytes,
		},
		Signatures:                 sigs,
		AdditionalVariableMessages: vars,
	}
}

// executeAndDecodeProve runs the Prove operation and decodes the response
func (s *ftdcProveTestSetup) executeAndDecodeProve(t *testing.T, instruction *instruction.DataFixed, signatures []hexutil.Bytes, signers []common.Address) (*ftdc.ProveResponse, error) {
	t.Helper()

	res, _, err := s.processor.Prove(types.Threshold, instruction, signatures, signers, s.policy)
	if err != nil {
		return nil, err
	}

	var proveResponse ftdc.ProveResponse
	err = json.Unmarshal(res, &proveResponse)
	require.NoError(t, err)

	return &proveResponse, nil
}

func TestFTDCProveBasicFlow(t *testing.T) {
	setup := setupFTDCProveTest(t)
	proc := setup.setupInstructionProcessor()

	// Use DP threshold >= 50% to satisfy the one-above-50 rule with cosigners (1/2)
	request := setup.buildFTDCRequest(utils.ToHash("PMWMultisigAccountConfigured"), utils.ToHash("XRP"), 6000, setup.defaultRequestBody)
	instruction := setup.buildInstruction(t, request, setup.defaultResponseBody, setup.cosigners[:2], 1, setup.defaultTimestamp)

	// Build action and process via instruction processor
	action := setup.buildActionWithPolicySigners(t, instruction, request, setup.defaultResponseBody, setup.cosigners[:2], 1, setup.privKeys)
	res := proc.Process(action)
	require.Equal(t, uint8(1), res.Status)

	// Decode result data into ProveResponse for assertions
	var proveResponse ftdc.ProveResponse
	err := json.Unmarshal(res.Data, &proveResponse)
	require.NoError(t, err)

	// Verify response header
	responseHeader, err := ftdc.DecodeResponse(proveResponse.ResponseHeader)
	require.NoError(t, err)

	require.Equal(t, request.Header.AttestationType, responseHeader.AttestationType)
	require.Equal(t, request.Header.SourceId, responseHeader.SourceId)
	require.Equal(t, request.Header.ThresholdBIPS, responseHeader.ThresholdBIPS)
	require.Equal(t, instruction.Cosigners, responseHeader.Cosigners)
	require.Equal(t, instruction.CosignersThreshold, responseHeader.CosignersThreshold)
	require.Equal(t, setup.defaultTimestamp, responseHeader.Timestamp)

	// Verify request and response bodies are preserved
	require.Equal(t, request.RequestBody, []byte(proveResponse.RequestBody))
	require.Equal(t, setup.defaultResponseBody, []byte(proveResponse.ResponseBody))

	// Verify signatures present
	require.NotEmpty(t, proveResponse.TEESignature)
	require.NotEmpty(t, proveResponse.DataProviderSignatures)
	require.NotEmpty(t, proveResponse.CosignerSignatures)
}

func TestFTDCProveNoCosigners(t *testing.T) {
	setup := setupFTDCProveTest(t)

	request := setup.defaultFTDCRequest()
	instruction := setup.buildInstruction(t, request, setup.defaultResponseBody, []common.Address{}, 0, setup.defaultTimestamp)

	// Sign with all data providers
	signatures, signers := setup.signFTDCMessage(t, request, setup.defaultResponseBody, []common.Address{}, 0, setup.defaultTimestamp, setup.privKeys)

	proveResponse, err := setup.executeAndDecodeProve(t, instruction, signatures, signers)
	require.NoError(t, err)
	require.NotNil(t, proveResponse)

	// Verify no cosigner signatures
	require.Empty(t, proveResponse.CosignerSignatures)
}

func TestFTDCProveInvalidRequestEncoding(t *testing.T) {
	setup := setupFTDCProveTest(t)

	instruction := setup.buildDefaultInstruction(t)

	instruction.OriginalMessage = []byte{0x01, 0x02, 0x03}
	_, err := setup.executeAndDecodeProve(t, instruction, []hexutil.Bytes{}, []common.Address{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decode FTDC prove request")

	instruction.OriginalMessage = []byte{}
	_, err = setup.executeAndDecodeProve(t, instruction, []hexutil.Bytes{}, []common.Address{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decode FTDC prove request")

	instruction.OriginalMessage = nil
	_, err = setup.executeAndDecodeProve(t, instruction, []hexutil.Bytes{}, []common.Address{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decode FTDC prove request")
}

func TestFTDCProveSignatureCountMismatch(t *testing.T) {
	setup := setupFTDCProveTest(t)

	request := setup.defaultFTDCRequest()
	instruction := setup.buildDefaultInstruction(t)

	signatures, signers := setup.signFTDCMessage(t, request, setup.defaultResponseBody, setup.cosigners[:2], 1, setup.defaultTimestamp, setup.privKeys[:10])

	// Add extra signer without signature
	signers = append(signers, setup.signers[50])

	_, err := setup.executeAndDecodeProve(t, instruction, signatures, signers)
	require.Error(t, err)
	require.Contains(t, err.Error(), "signature count does not match signer count")
}

func TestFTDCProveInvalidSignature(t *testing.T) {
	setup := setupFTDCProveTest(t)

	request := setup.defaultFTDCRequest()
	instruction := setup.buildDefaultInstruction(t)

	signatures, signers := setup.signFTDCMessage(t, request, setup.defaultResponseBody, setup.cosigners[:2], 1, setup.defaultTimestamp, setup.privKeys[:10])

	// Corrupt one signature
	signatures[2] = hexutil.Bytes{0x01, 0x02, 0x03}

	_, err := setup.executeAndDecodeProve(t, instruction, signatures, signers)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid signature")
}

func TestFTDCProveThresholdsThroughProcessorProcess(t *testing.T) {
	setup := setupFTDCProveTest(t)
	proc := setup.setupInstructionProcessor()

	// Case 1: Below minimum DP threshold (3999) should fail
	request := setup.buildFTDCRequest(utils.ToHash("TestAttestation"), utils.ToHash("XRP"), 3999, setup.defaultRequestBody)
	instr := setup.buildInstruction(t, request, setup.defaultResponseBody, []common.Address{}, 0, setup.defaultTimestamp)
	action := setup.buildActionWithPolicySigners(t, instr, request, setup.defaultResponseBody, []common.Address{}, 0, setup.privKeys)
	res := proc.Process(action)
	require.Equal(t, uint8(0), res.Status)
	require.Contains(t, res.Log, "data providers threshold too low")

	// Case 5: One-above-50 rule fail: DP=4000 (<50%), cosigner threshold = 2/4 (==50%)
	request = setup.buildFTDCRequest(utils.ToHash("TestAttestation"), utils.ToHash("XRP"), 4000, setup.defaultRequestBody)
	cos := setup.cosigners[:4]
	instr = setup.buildInstruction(t, request, setup.defaultResponseBody, cos, 2, setup.defaultTimestamp)
	action = setup.buildActionWithPolicySigners(t, instr, request, setup.defaultResponseBody, cos, 2, setup.privKeys)
	res = proc.Process(action)
	require.Equal(t, uint8(0), res.Status)
	require.Contains(t, res.Log, "one threshold should be above 50%")

	// Case 3: Zero BIPS (default 50%) should pass
	request = setup.buildFTDCRequest(utils.ToHash("TestAttestation"), utils.ToHash("XRP"), 0, setup.defaultRequestBody)
	instr = setup.buildInstruction(t, request, setup.defaultResponseBody, []common.Address{}, 0, setup.defaultTimestamp)
	action = setup.buildActionWithPolicySigners(t, instr, request, setup.defaultResponseBody, []common.Address{}, 0, setup.privKeys)
	res = proc.Process(action)
	require.Equal(t, uint8(1), res.Status)

	// Case 4: Max DP threshold (9999) should pass with all providers
	request = setup.buildFTDCRequest(utils.ToHash("TestAttestation"), utils.ToHash("XRP"), 9999, setup.defaultRequestBody)
	instr = setup.buildInstruction(t, request, setup.defaultResponseBody, []common.Address{}, 0, setup.defaultTimestamp)
	action = setup.buildActionWithPolicySigners(t, instr, request, setup.defaultResponseBody, []common.Address{}, 0, setup.privKeys)
	res = proc.Process(action)
	require.Equal(t, uint8(1), res.Status)

	// Case 6: One-above-50 rule pass: DP=4000 (<50%), cosigner threshold = 3/5 (>50%)
	request = setup.buildFTDCRequest(utils.ToHash("TestAttestation"), utils.ToHash("XRP"), 4000, setup.defaultRequestBody)
	cos = setup.cosigners[:5]
	instr = setup.buildInstruction(t, request, setup.defaultResponseBody, cos, 3, setup.defaultTimestamp)
	action = setup.buildActionWithPolicySigners(t, instr, request, setup.defaultResponseBody, cos, 3, setup.privKeys)
	res = proc.Process(action)
	require.Equal(t, uint8(1), res.Status)
}

func TestFTDCProveSignatureEdgeCases(t *testing.T) {
	setup := setupFTDCProveTest(t)
	proc := setup.setupInstructionProcessor()

	// Base request: default 50% DP threshold (BIPS=0), no cosigners
	request := setup.buildFTDCRequest(utils.ToHash("TestAttestation"), utils.ToHash("XRP"), 0, setup.defaultRequestBody)
	instr := setup.buildInstruction(t, request, setup.defaultResponseBody, []common.Address{}, 0, setup.defaultTimestamp)

	// 1) Not enough provider signatures (10% < 50%)
	pks1 := setup.privKeys[:10]
	action := setup.buildActionWithPolicySigners(t, instr, request, setup.defaultResponseBody, []common.Address{}, 0, pks1)
	res := proc.Process(action)
	require.Equal(t, uint8(0), res.Status)
	require.Contains(t, res.Log, "data providers threshold not reached")

	// 2) Empty signatures array
	none := []*ecdsa.PrivateKey{}
	action = setup.buildActionWithPolicySigners(t, instr, request, setup.defaultResponseBody, []common.Address{}, 0, none)
	res = proc.Process(action)
	require.Equal(t, uint8(0), res.Status)
	require.Contains(t, res.Log, "data providers threshold not reached")

	// 3) Duplicate signer (double signing)
	dup := []*ecdsa.PrivateKey{setup.privKeys[0], setup.privKeys[0], setup.privKeys[1], setup.privKeys[2], setup.privKeys[3], setup.privKeys[4], setup.privKeys[5], setup.privKeys[6], setup.privKeys[7], setup.privKeys[8], setup.privKeys[9], setup.privKeys[10], setup.privKeys[11], setup.privKeys[12], setup.privKeys[13], setup.privKeys[14], setup.privKeys[15], setup.privKeys[16], setup.privKeys[17], setup.privKeys[18], setup.privKeys[19], setup.privKeys[20], setup.privKeys[21], setup.privKeys[22], setup.privKeys[23], setup.privKeys[24], setup.privKeys[25], setup.privKeys[26], setup.privKeys[27], setup.privKeys[28], setup.privKeys[29], setup.privKeys[30], setup.privKeys[31], setup.privKeys[32], setup.privKeys[33], setup.privKeys[34], setup.privKeys[35], setup.privKeys[36], setup.privKeys[37], setup.privKeys[38], setup.privKeys[39], setup.privKeys[40], setup.privKeys[41], setup.privKeys[42], setup.privKeys[43], setup.privKeys[44], setup.privKeys[45], setup.privKeys[46], setup.privKeys[47], setup.privKeys[48]}
	action = setup.buildActionWithPolicySigners(t, instr, request, setup.defaultResponseBody, []common.Address{}, 0, dup)
	res = proc.Process(action)
	require.Equal(t, uint8(0), res.Status)
	require.Contains(t, res.Log, "double signing")
}

// Ensure data provider signatures are sorted by voter index in checkResponseSignatures
func TestFTDCProveDataProviderSignaturesAreSorted(t *testing.T) {
	setup := setupFTDCProveTest(t)

	request := setup.buildFTDCRequest(utils.ToHash("TestAttestation"), utils.ToHash("XRP"), 5000, setup.defaultRequestBody)
	msgHash, _, _, err := ftdc.HashMessage(request, setup.defaultResponseBody, setup.cosigners[:3], 2, setup.defaultTimestamp)
	require.NoError(t, err)

	order := []int{10, 2, 25, 7, 0, 18, 3}
	sigs := make([]hexutil.Bytes, 0, len(order))
	signers := make([]common.Address, 0, len(order))
	for _, i := range order {
		sig, se := utils.Sign(msgHash[:], setup.privKeys[i])
		require.NoError(t, se)
		sigs = append(sigs, sig)
		signers = append(signers, setup.signers[i])
	}

	dpSigs, _, err := checkResponseSignatures(msgHash, sigs, signers, setup.policy.Voters, setup.cosigners[:3])
	require.NoError(t, err)

	for i := 1; i < len(dpSigs); i++ {
		require.LessOrEqual(t, dpSigs[i-1].Index, dpSigs[i].Index, fmt.Sprintf("indices not sorted at %d: %d > %d", i, dpSigs[i-1].Index, dpSigs[i].Index))
	}
}

// Verifies we accept signatures for current and previous epoch policies, and reject older
func TestFTDCProvePolicyWindowLastTwoEpochs(t *testing.T) {
	setup := setupFTDCProveTest(t)
	proc := setup.setupInstructionProcessor()

	// Create policies for epoch+1 and epoch+2 (advance active policy twice)
	epoch2 := setup.epochID + 1
	epoch3 := setup.epochID + 2

	policy2 := testutils.GenerateRandomPolicyData(t, epoch2, setup.signers, 2222)
	err := setup.pStorage.SetActiveSigningPolicy(policy2)
	require.NoError(t, err)

	policy3 := testutils.GenerateRandomPolicyData(t, epoch3, setup.signers, 3333)
	err = setup.pStorage.SetActiveSigningPolicy(policy3)
	require.NoError(t, err)

	// Base request
	request := setup.buildFTDCRequest(utils.ToHash("TestAttestation"), utils.ToHash("XRP"), 0, setup.defaultRequestBody)

	run := func(epoch uint32, expectOK bool) {
		instr := setup.buildInstruction(t, request, setup.defaultResponseBody, []common.Address{}, 0, setup.defaultTimestamp)
		instr.RewardEpochID = epoch
		action := setup.buildActionWithPolicySigners(t, instr, request, setup.defaultResponseBody, []common.Address{}, 0, setup.privKeys)
		res := proc.Process(action)
		if expectOK {
			require.Equal(t, uint8(1), res.Status, fmt.Sprintf("expected success for epoch %d, log=%s", epoch, res.Log))
		} else {
			require.Equal(t, uint8(0), res.Status)
			require.Contains(t, res.Log, "signing policy too old")
		}
	}

	// Active is epoch3: accept epoch3 and epoch2; reject epoch1
	run(epoch3, true)
	run(epoch2, true)
	run(setup.epochID, false)
}
