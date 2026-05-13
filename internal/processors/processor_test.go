package processors_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	commonpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/random"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/fdc2"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/payments"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/verification"
	vrfstruct "github.com/flare-foundation/go-flare-common/pkg/tee/structs/vrf"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/signing"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/signing/secp256k1"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/signing/signer"

	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/internal/router"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/fdc"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/wallets/backup"
	"github.com/flare-foundation/tee-node/pkg/wallets/vrf"

	"github.com/flare-foundation/tee-node/pkg/wallets"

	"github.com/flare-foundation/tee-node/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestProcessorsEndToEnd(t *testing.T) {
	testNode, pStorage, wStorage := testutils.Setup(t)

	numVoters, startingEpochID := 100, uint32(1)
	finalEpochID := startingEpochID + 1

	providerAddresses, providerPrivKeys, _ := testutils.GenerateRandomKeys(t, numVoters)

	numAdmins := 3
	adminPubKeys := make([]*ecdsa.PublicKey, numAdmins)
	adminPrivKeys := make([]*ecdsa.PrivateKey, numAdmins)
	var err error
	for i := range numAdmins - 1 {
		adminPrivKeys[i], err = crypto.GenerateKey()
		require.NoError(t, err)
		adminPubKeys[i] = &adminPrivKeys[i].PublicKey
	}

	// make one provider also admin
	adminPrivKeys[numAdmins-1] = providerPrivKeys[0]
	adminPubKeys[numAdmins-1] = &providerPrivKeys[0].PublicKey

	// change type
	adminWalletPublicKeys := make([]wallet.PublicKey, len(adminPubKeys))
	for i, pubKey := range adminPubKeys {
		pk := types.PubKeyToStruct(pubKey)
		adminWalletPublicKeys[i] = wallet.PublicKey{
			X: pk.X,
			Y: pk.Y,
		}
	}

	// Cosigners for the common (XRP) wallet. One of them overlaps a data
	// provider, to exercise the provider/cosigner overlap path.
	numCosigners := 3
	cosignerPrivKeys := make([]*ecdsa.PrivateKey, numCosigners)
	cosignerAddresses := make([]common.Address, numCosigners)
	for i := range numCosigners - 1 {
		cosignerPrivKeys[i], err = crypto.GenerateKey()
		require.NoError(t, err)
		cosignerAddresses[i] = crypto.PubkeyToAddress(cosignerPrivKeys[i].PublicKey)
	}
	cosignerPrivKeys[numCosigners-1] = providerPrivKeys[1]
	cosignerAddresses[numCosigners-1] = crypto.PubkeyToAddress(providerPrivKeys[1].PublicKey)
	cosignersThreshold := uint64(numCosigners)

	mainActionInfoChan := make(chan *types.Action, 100)
	readActionInfoChan := make(chan *types.Action, 100)
	actionResponseChan := make(chan *types.ActionResponse, 100)
	proxyPort := 8008 // Use different port for MockProxy
	go MockProxy(t, proxyPort, mainActionInfoChan, readActionInfoChan, actionResponseChan)

	pc := settings.NewConfigServer(settings.ConfigPort, testNode) // Use original port for ProxyConfigureServer

	go pc.Serve() //nolint:errcheck

	r := router.NewPMWRouter(testNode, wStorage, pStorage, pc.ProxyURL)

	go r.Run(testNode)
	time.Sleep(1 * time.Second)

	setProxyURL(t, proxyPort, settings.ConfigPort)

	teeID, teePubKey := getTeeInfo(t, readActionInfoChan, actionResponseChan)

	initializePolicy(t, mainActionInfoChan, actionResponseChan, providerPrivKeys, providerAddresses,
		startingEpochID)

	var walletID = common.HexToHash("0xabcdef")
	var keyID = uint64(1)
	walletProof := generateWallet(t, mainActionInfoChan, actionResponseChan, teeID, walletID, keyID,
		providerPrivKeys, adminWalletPublicKeys, cosignerAddresses, cosignersThreshold, finalEpochID, wStorage, wallets.XRPType, wallets.XRPSignAlgo)
	require.False(t, walletProof.Restored)

	var vrfWalletID = common.HexToHash("0x123456")
	var vrfKeyID = uint64(1)
	randWalletProof := generateWallet(t, mainActionInfoChan, actionResponseChan, teeID, vrfWalletID, vrfKeyID,
		providerPrivKeys, adminWalletPublicKeys, nil, 0, finalEpochID, wStorage, wallets.EVMType, wallets.VRFAlgo)
	proveVRFRandomness(t, mainActionInfoChan, actionResponseChan, teeID, vrfWalletID, vrfKeyID, randWalletProof.PublicKey, providerPrivKeys, finalEpochID)

	signTransaction(t, mainActionInfoChan, actionResponseChan, teeID, walletID, keyID, providerPrivKeys, cosignerPrivKeys, cosignerAddresses, cosignersThreshold, finalEpochID, wStorage)

	walletBackup := getBackup(t, readActionInfoChan, actionResponseChan, teeID, walletID, keyID)
	vrfWalletBackup := getBackup(t, readActionInfoChan, actionResponseChan, teeID, vrfWalletID, vrfKeyID)

	nonce := big.NewInt(1)
	deleteWallet(t, mainActionInfoChan, actionResponseChan, teeID, walletID, keyID, providerPrivKeys, finalEpochID, nonce, wStorage)
	nonce.Add(nonce, common.Big1)
	deleteWallet(t, mainActionInfoChan, actionResponseChan, teeID, vrfWalletID, vrfKeyID, providerPrivKeys, finalEpochID, nonce, wStorage)
	nonce.Add(nonce, common.Big1)

	recoveredWalletProof := recoverWallet(t, mainActionInfoChan, actionResponseChan, teeID, teePubKey, walletID, keyID,
		providerPrivKeys, adminPrivKeys, finalEpochID, nonce, walletBackup, wStorage)
	walletProof.Restored = true
	walletProof.Nonce = nonce
	require.Equal(t, walletProof, recoveredWalletProof)

	nonce.Add(nonce, common.Big1)
	recoveredVRFWalletProof := recoverWallet(t, mainActionInfoChan, actionResponseChan, teeID, teePubKey, vrfWalletID, vrfKeyID,
		providerPrivKeys, adminPrivKeys, finalEpochID, nonce, vrfWalletBackup, wStorage)
	randWalletProof.Restored = true
	randWalletProof.Nonce = nonce
	require.Equal(t, randWalletProof, recoveredVRFWalletProof)

	getTeeAttestation(t, mainActionInfoChan, actionResponseChan, teeID,
		providerPrivKeys, finalEpochID)

	fdcProve(t, mainActionInfoChan, actionResponseChan, teeID, providerPrivKeys, adminPrivKeys, finalEpochID)

	updatePolicy(t, mainActionInfoChan, actionResponseChan, providerPrivKeys, providerAddresses, finalEpochID+1)
}

// updatePolicy builds a new signing policy for the next epoch (same voters as
// the currently active policy, with a different random seed so a few weights
// shift) and submits it signed by a super-majority of the current providers.
func updatePolicy(t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	privKeys []*ecdsa.PrivateKey,
	addresses []common.Address,
	newEpochID uint32,
) {
	t.Helper()

	// "Slightly changed" policy: same voters but fresh seed so weights differ.
	newPolicy := testutils.GenerateRandomPolicyData(t, newEpochID, addresses, int64(54321))

	// Sign the new policy with every provider from the active policy. The
	// processor only needs > threshold, so all signing is well over the bar.
	signed := testutils.BuildMultiSignedPolicy(t, newPolicy.RawBytes(), privKeys)

	pubKeys := make([]types.PublicKey, len(privKeys))
	for i, voter := range privKeys {
		pubKeys[i] = types.PubKeyToStruct(&voter.PublicKey)
	}

	req := &types.UpdatePolicyRequest{
		NewPolicy:  signed,
		PublicKeys: pubKeys,
	}

	action := testutils.BuildMockDirectAction(t, op.Policy, op.UpdatePolicy, req)
	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status, actionResponse.Result.Log)

	// Confirm the new policy is what got installed by hashing a round-trip
	// through the commonpolicy codec.
	installed, _, err := commonpolicy.FromRawBytes(newPolicy.RawBytes())
	require.NoError(t, err)
	require.Equal(t, newEpochID, installed.RewardEpochID)
}

func setProxyURL(t *testing.T, proxyPort, setProxyPort int) {
	t.Helper()

	url := fmt.Sprintf("http://localhost:%d", proxyPort)
	request := types.ConfigureProxyURLRequest{
		URL: &url,
	}

	client := http.Client{
		Timeout: settings.ProxyTimeout,
	}
	requestBody, err := json.Marshal(request)
	require.NoError(t, err)

	r, err := client.Post(fmt.Sprintf("http://localhost:%d%s", setProxyPort, settings.SetProxyURLEndpoint), "application/json", bytes.NewBuffer(requestBody))
	require.NoError(t, err)
	require.Equal(t, r.StatusCode, http.StatusOK)

	err = r.Body.Close()
	require.NoError(t, err)
}

func initializePolicy(t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	privKeys []*ecdsa.PrivateKey,
	addresses []common.Address,
	startingEpochID uint32,
) {
	t.Helper()

	// initialize policy
	randSeed := int64(12345)

	nextPolicy := testutils.GenerateRandomPolicyData(t, startingEpochID+1, addresses, randSeed)

	pubKeys := make([]types.PublicKey, len(privKeys))
	for i, voter := range privKeys {
		pubKeys[i] = types.PubKeyToStruct(&voter.PublicKey)
	}
	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: nextPolicy.RawBytes(),
		PublicKeys:         pubKeys,
	}

	action := testutils.BuildMockDirectAction(t, op.Policy, op.InitializePolicy, req)

	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status, actionResponse.Result.Log)
}

func getTeeInfo(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
) (common.Address, *ecdsa.PublicKey) {
	t.Helper()

	challenge, err := random.Hash()
	require.NoError(t, err)
	req := &types.TeeInfoRequest{
		Challenge: challenge,
	}
	action := testutils.BuildMockDirectAction(t, op.Get, op.TEEInfo, req)

	actionInfoChan <- action

	actionResponse := <-actionResponseChan

	require.Equal(t, uint8(1), actionResponse.Result.Status)

	var teeInfoResponse types.TeeInfoResponse
	err = json.Unmarshal(actionResponse.Result.Data, &teeInfoResponse)
	require.NoError(t, err)

	teePubKey, err := types.ParsePubKey(teeInfoResponse.TeeInfo.PublicKey)
	require.NoError(t, err)

	teeID := crypto.PubkeyToAddress(*teePubKey)

	err = utils.VerifySignature(actionResponse.Result.Hash(), actionResponse.Signature, teeID)
	require.NoError(t, err)

	return teeID, teePubKey
}

func generateWallet(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	teeID common.Address,
	walletID [32]byte,
	keyID uint64,
	privKeys []*ecdsa.PrivateKey,
	adminWalletPublicKeys []wallet.PublicKey,
	cosigners []common.Address,
	cosignersThreshold uint64,
	rewardEpochID uint32,
	wStorage *wallets.Storage,
	keyType common.Hash,
	signingAlgo common.Hash,
) *wallet.IWalletKeyManagerKeyExistence {
	t.Helper()

	if cosigners == nil {
		cosigners = make([]common.Address, 0)
	}

	originalMessage := wallet.IWalletKeyManagerKeyGenerate{
		TeeId:       teeID,
		WalletId:    walletID,
		KeyId:       keyID,
		KeyType:     keyType,
		SigningAlgo: signingAlgo,
		ConfigConstants: wallet.IWalletKeyManagerKeyConfigConstants{
			AdminsPublicKeys:   adminWalletPublicKeys,
			AdminsThreshold:    uint64(len(adminWalletPublicKeys)),
			Cosigners:          cosigners,
			CosignersThreshold: cosignersThreshold,
		},
	}
	originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[op.KeyGenerate]}.Pack(originalMessage)
	require.NoError(t, err)

	// generate action sent when threshold reached
	action := testutils.BuildMockInstructionAction(
		t, op.Wallet, op.KeyGenerate, originalMessageEncoded, privKeys, teeID, rewardEpochID, nil, nil, nil, 0, types.Threshold, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	response := <-actionResponseChan
	t.Log(response.Result.Log)
	require.Equal(t, uint8(1), response.Result.Status)
	err = utils.VerifySignature(response.Result.Hash(), response.Signature, teeID)
	require.NoError(t, err)

	walletExistenceProof, err := wallets.ExtractKeyExistence(response.Result.Data, teeID)
	require.NoError(t, err)

	newWallet, err := wStorage.Get(wallets.KeyIDPair{WalletID: walletID, KeyID: keyID})
	require.NoError(t, err)

	require.Equal(t, newWallet.WalletID, common.Hash(walletExistenceProof.WalletId))
	require.Equal(t, newWallet.KeyID, walletExistenceProof.KeyId)

	// generate action sent when voting closed
	action = testutils.BuildMockInstructionAction(
		t, op.Wallet, op.KeyGenerate, originalMessageEncoded, privKeys, teeID, rewardEpochID, nil, nil, nil, 0, types.End, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	response = <-actionResponseChan

	t.Log(response.Result.Log)
	require.Equal(t, uint8(1), response.Result.Status)

	err = utils.VerifySignature(response.Result.Hash(), response.Signature, teeID)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(response.Result.Data, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeID)
	require.NoError(t, err)

	return walletExistenceProof
}

func proveVRFRandomness(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	teeID common.Address,
	walletID [32]byte,
	keyID uint64,
	publicKey []byte,
	privKeys []*ecdsa.PrivateKey,
	rewardEpochID uint32,
) {
	t.Helper()

	pk, err := types.ParsePubKeyBytes(publicKey)
	require.NoError(t, err)

	nonce := make([]byte, 32)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	originalMessage := vrfstruct.IVrfVrfInstructionMessage{
		WalletId: walletID,
		KeyId:    keyID,
		Nonce:    nonce,
	}
	originalMessageEncoded, err := abi.Arguments{vrfstruct.MessageArguments[op.VRF]}.Pack(originalMessage)
	require.NoError(t, err)

	action := testutils.BuildMockInstructionAction(
		t, op.Wallet, op.Command("VRF"), originalMessageEncoded, privKeys, teeID, rewardEpochID, nil, nil, nil, 0, types.Threshold, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status, actionResponse.Result.Log)
	err = utils.VerifySignature(actionResponse.Result.Hash(), actionResponse.Signature, teeID)
	require.NoError(t, err)

	var proveResp types.ProveRandomnessResponse
	err = json.Unmarshal(actionResponse.Result.Data, &proveResp)
	require.NoError(t, err)
	require.Equal(t, common.Hash(walletID), proveResp.WalletID)
	require.Equal(t, keyID, proveResp.KeyID)
	require.Equal(t, nonce, []byte(proveResp.Nonce))

	err = vrf.VerifyRandomness(&proveResp.Proof, pk, nonce)
	require.NoError(t, err)
	randomness, err := proveResp.Proof.RandomnessFromProof()
	require.NoError(t, err)
	require.NotEqual(t, common.Hash{}, randomness)

	action = testutils.BuildMockInstructionAction(
		t, op.Wallet, op.Command("VRF"), originalMessageEncoded, privKeys, teeID, rewardEpochID, nil, nil, nil, 0, types.End, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	actionResponse = <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status, actionResponse.Result.Log)
	err = utils.VerifySignature(actionResponse.Result.Hash(), actionResponse.Signature, teeID)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(actionResponse.Result.Data, &signerSequence)
	require.NoError(t, err)
	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeID)
	require.NoError(t, err)
}

func signTransaction(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	teeID common.Address,
	walletID [32]byte,
	keyID uint64,
	providerPrivKeys []*ecdsa.PrivateKey,
	cosignerPrivKeys []*ecdsa.PrivateKey,
	cosignerAddresses []common.Address,
	cosignersThreshold uint64,
	rewardEpochID uint32,
	wStorage *wallets.Storage,
) {
	t.Helper()

	originalMessage := payments.ITeePaymentsPaymentInstructionMessage{
		WalletId:         walletID,
		TeeIdKeyIdPairs:  []payments.TeeIdKeyIdPair{{TeeId: teeID, KeyId: keyID}},
		SenderAddress:    "ravbaTwRkNqecy9Zdw8zwrw4uK5awjqhFd",
		RecipientAddress: "rrrrrrrrrrrrrrrrrNAMEtxvNvQ",
		Amount:           big.NewInt(1000000000),
		MaxFee:           big.NewInt(10),
		FeeSchedule:      []byte{0x27, 0x10, 0x00, 0x01}, // 100% of MaxFee, 1s delay
		PaymentReference: [32]byte{},
		Nonce:            0,
		SubNonce:         0,
		BatchEndTs:       0,
	}

	originalMessageEncoded, err := abi.Arguments{payments.MessageArguments[op.Pay]}.Pack(originalMessage)
	require.NoError(t, err)

	// The XRP processor enforces CheckMatchingCosigners, so the instruction's
	// cosigner list / threshold must exactly match the wallet key's. Also sign
	// with all cosigners so the cosigner threshold is reached.
	signingKeys := mergePrivKeys(providerPrivKeys, cosignerPrivKeys)

	action := testutils.BuildMockInstructionAction(
		t, op.XRP, op.Pay, originalMessageEncoded, signingKeys, teeID, rewardEpochID, []byte{}, nil, cosignerAddresses, cosignersThreshold, types.Threshold, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	// The XRP sign processor posts two responses for Threshold: the goroutine's
	// signed result (status=1) and the router's acknowledgment (status=2).
	// Collect both and verify the goroutine's signed response.
	var actionResponse *types.ActionResponse
	for range 2 {
		select {
		case r := <-actionResponseChan:
			if r.Result.Status == 1 {
				actionResponse = r
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for XRP Threshold response")
		}
	}
	require.NotNil(t, actionResponse)
	err = utils.VerifySignature(actionResponse.Result.Hash(), actionResponse.Signature, teeID)
	require.NoError(t, err)

	// Verify the XRP multisig signatures the TEE produced are cryptographically
	// valid and that the wallet's address is the one signing.
	var txs types.XRPSignResponse
	err = json.Unmarshal(actionResponse.Result.Data, &txs)
	require.NoError(t, err)
	require.NotEmpty(t, txs, "expected at least one signed XRP transaction")
	signedWallet, err := wStorage.Get(wallets.KeyIDPair{WalletID: walletID, KeyID: keyID})
	require.NoError(t, err)
	verifyXRPSignatures(t, txs, signedWallet)

	// generate action sent when voting closed
	action = testutils.BuildMockInstructionAction(
		t, op.XRP, op.Pay, originalMessageEncoded, signingKeys, teeID, rewardEpochID, []byte{}, nil, cosignerAddresses, cosignersThreshold, types.End, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	actionResponse = <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
	err = utils.VerifySignature(actionResponse.Result.Hash(), actionResponse.Signature, teeID)
	require.NoError(t, err)

	verifyRewardingData(t, action, actionResponse, teeID)
}

// mergePrivKeys concatenates the two key slices while skipping any cosigner
// key whose address already appears in the provider slice, so each signer
// signs at most once in the action.
func mergePrivKeys(providers, cosigners []*ecdsa.PrivateKey) []*ecdsa.PrivateKey {
	seen := make(map[common.Address]bool, len(providers))
	for _, k := range providers {
		seen[crypto.PubkeyToAddress(k.PublicKey)] = true
	}
	merged := make([]*ecdsa.PrivateKey, 0, len(providers)+len(cosigners))
	merged = append(merged, providers...)
	for _, k := range cosigners {
		if seen[crypto.PubkeyToAddress(k.PublicKey)] {
			continue
		}
		merged = append(merged, k)
	}
	return merged
}

// verifyXRPSignatures asserts every XRPL multisig signature in txs validates
// and that the wallet's XRPL address appears as a signer in each tx.
func verifyXRPSignatures(t *testing.T, txs types.XRPSignResponse, w *wallets.Wallet) {
	t.Helper()
	expectedAddr := ""
	if w != nil {
		expectedAddr = secp256k1WalletAddress(w)
	}
	for i, tx := range txs {
		signersAny, ok := tx["Signers"].([]any)
		require.True(t, ok, "tx[%d] must have Signers field", i)
		require.NotEmpty(t, signersAny, "tx[%d] must have at least one signer", i)
		foundSelf := false
		for j, sAny := range signersAny {
			sMap, ok := sAny.(map[string]any)
			require.True(t, ok, "tx[%d] signer[%d] must be a map", i, j)
			s, err := signer.Parse(sMap)
			require.NoError(t, err, "tx[%d] signer[%d] parse", i, j)
			valid, err := signing.ValidateMultiSig(tx, s)
			require.NoError(t, err, "tx[%d] signer[%d] validate", i, j)
			require.True(t, valid, "tx[%d] signer[%d] signature invalid", i, j)
			if s.Account == expectedAddr {
				foundSelf = true
			}
		}
		if expectedAddr != "" {
			require.True(t, foundSelf, "tx[%d]: wallet address %s not present in Signers", i, expectedAddr)
		}
	}
}

// secp256k1WalletAddress returns the XRPL classic address for the given wallet.
func secp256k1WalletAddress(w *wallets.Wallet) string {
	prv := wallets.ToECDSAUnsafe(w.PrivateKey)
	return secp256k1.PrvToAddress(prv)
}

// verifyRewardingData asserts that the End-phase response carries a well-formed
// RewardingData: the TEE signature over the voteHash is valid, and the voteHash
// is exactly the one the node should have produced by iteratively hashing the
// (signature, variableMessage, timestamp) triples for the instruction.
func verifyRewardingData(t *testing.T, endAction *types.Action, response *types.ActionResponse, teeID common.Address) {
	t.Helper()

	var rewardingData types.RewardingData
	err := json.Unmarshal(response.Result.Data, &rewardingData)
	require.NoError(t, err)

	// TEE signed the voteHash.
	err = utils.VerifySignature(rewardingData.VoteSequence.VoteHash[:], rewardingData.Signature, teeID)
	require.NoError(t, err)

	// Recompute the voteHash from the original instruction + signature chain.
	var instructionDataFixed instruction.DataFixed
	err = json.Unmarshal(endAction.Data.Message, &instructionDataFixed)
	require.NoError(t, err)

	instructionHash, err := instructionDataFixed.HashFixed()
	require.NoError(t, err)
	require.Equal(t, instructionHash, rewardingData.VoteSequence.InstructionHash)

	expectedVoteHash, err := instructionDataFixed.InitialVoteHash()
	require.NoError(t, err)

	variableMessages := endAction.AdditionalVariableMessages
	if len(variableMessages) == 0 {
		variableMessages = make([]hexutil.Bytes, len(endAction.Signatures))
	}
	for i := range endAction.Signatures {
		expectedVoteHash, err = instruction.NextVoteHash(
			expectedVoteHash,
			uint64(i),
			endAction.Signatures[i],
			variableMessages[i],
			endAction.Timestamps[i],
		)
		require.NoError(t, err)
	}
	require.Equal(t, expectedVoteHash, rewardingData.VoteSequence.VoteHash)

	require.Equal(t, instructionDataFixed.RewardEpochID, rewardingData.VoteSequence.RewardEpochID)
	require.Equal(t, teeID, rewardingData.VoteSequence.TeeID)
	require.Len(t, rewardingData.VoteSequence.Signatures, len(endAction.Signatures))
	require.Len(t, rewardingData.VoteSequence.AdditionalVariableMessageHashes, len(endAction.Signatures))
}

func deleteWallet(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	teeID common.Address,
	walletID [32]byte,
	keyID uint64,
	privKeys []*ecdsa.PrivateKey,
	rewardEpochID uint32,
	nonce *big.Int,
	wStorage *wallets.Storage,
) {
	t.Helper()

	originalMessage := wallet.IWalletKeyManagerKeyDelete{
		TeeId:    teeID,
		WalletId: walletID,
		KeyId:    keyID,
		Nonce:    nonce,
	}
	originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[op.KeyDelete]}.Pack(originalMessage)
	require.NoError(t, err)

	action := testutils.BuildMockInstructionAction(
		t, op.Wallet, op.KeyDelete, originalMessageEncoded, privKeys, teeID, rewardEpochID, nil, nil, nil, 0, types.Threshold, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)

	_, err = wStorage.Get(wallets.KeyIDPair{WalletID: walletID, KeyID: keyID})
	require.Error(t, err)

	// generate action sent when voting closed
	action = testutils.BuildMockInstructionAction(
		t, op.Wallet, op.KeyDelete, originalMessageEncoded, privKeys, teeID, rewardEpochID, nil, nil, nil, 0, types.End, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	actionResponse = <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
	err = utils.VerifySignature(actionResponse.Result.Hash(), actionResponse.Signature, teeID)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(actionResponse.Result.Data, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeID)
	require.NoError(t, err)
}

func getBackup(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	teeID common.Address,
	walletID [32]byte,
	keyID uint64,
) *backup.WalletBackup {
	t.Helper()

	message := wallets.KeyIDPair{
		WalletID: walletID,
		KeyID:    keyID,
	}

	action := testutils.BuildMockDirectAction(t, op.Get, op.TEEBackup, message)

	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
	err := utils.VerifySignature(actionResponse.Result.Hash(), actionResponse.Signature, teeID)
	require.NoError(t, err)

	var backupResponse wallets.TEEBackupResponse
	err = json.Unmarshal(actionResponse.Result.Data, &backupResponse)
	require.NoError(t, err)

	var backup backup.WalletBackup
	err = json.Unmarshal(backupResponse.WalletBackup, &backup)
	require.NoError(t, err)

	err = backup.Check()
	require.NoError(t, err)

	return &backup
}

func recoverWallet(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	teeID common.Address,
	teePubKey *ecdsa.PublicKey,
	walletID [32]byte,
	keyID uint64,
	providersPrivKeys,
	adminsPrivKeys []*ecdsa.PrivateKey,
	rewardEpochID uint32,
	nonce *big.Int,
	walletBackup *backup.WalletBackup,
	wStorage *wallets.Storage,
) *wallet.IWalletKeyManagerKeyExistence {
	t.Helper()

	teePubKeyParsed := types.PubKeyToStruct(teePubKey)

	originalMessage := wallet.IWalletBackupManagerKeyDataProviderRestore{
		TeePublicKey: wallet.PublicKey{X: teePubKeyParsed.X, Y: teePubKeyParsed.Y},
		BackupUrl:    "blabla",
		Nonce:        nonce,
		BackupId: wallet.IWalletBackupManagerBackupId{
			TeeId:         teeID,
			WalletId:      walletID,
			KeyId:         keyID,
			KeyType:       walletBackup.KeyType,
			SigningAlgo:   walletBackup.SigningAlgo,
			PublicKey:     walletBackup.PublicKey,
			RewardEpochId: rewardEpochID,
			RandomNonce:   walletBackup.RandomNonce,
		},
	}

	originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[op.KeyDataProviderRestore]}.Pack(originalMessage)
	require.NoError(t, err)

	additionalFixedMessage := walletBackup.WalletBackupMetaData

	adminAndProvider := make(map[common.Address]int)
	adminAddresses := make([]common.Address, len(adminsPrivKeys))
	for j, adminPrivKey := range adminsPrivKeys {
		address := crypto.PubkeyToAddress(adminPrivKey.PublicKey)
		for _, providerPrivKey := range providersPrivKeys {
			if address == crypto.PubkeyToAddress(providerPrivKey.PublicKey) {
				adminAndProvider[address] = j
			}
		}
		adminAddresses[j] = address
	}
	adminsThreshold := uint64(len(adminAddresses))

	teeEciesPubKey, err := utils.ECDSAPubKeyToECIES(teePubKey)
	require.NoError(t, err)

	additionalVariableMessages := make([][]byte, 0, len(providersPrivKeys)+len(adminsPrivKeys))
	privKeys := make([]*ecdsa.PrivateKey, 0, len(providersPrivKeys)+len(adminsPrivKeys))
	for i, privKey := range providersPrivKeys {
		keySplit, err := backup.DecryptSplit(walletBackup.ProviderEncryptedParts.Splits[i], privKey)
		require.NoError(t, err)

		address := crypto.PubkeyToAddress(privKey.PublicKey)
		j, check := adminAndProvider[address]
		var plaintext []byte
		if !check {
			plaintext, err = json.Marshal(keySplit)
			require.NoError(t, err)
		} else {
			keySplitAdmin, err := backup.DecryptSplit(walletBackup.AdminEncryptedParts.Splits[j], privKey)
			require.NoError(t, err)
			var twoKeySplits [2]backup.KeySplit
			twoKeySplits[0] = *keySplit
			twoKeySplits[1] = *keySplitAdmin
			plaintext, err = json.Marshal(twoKeySplits)
			require.NoError(t, err)
		}

		cipher, err := ecies.Encrypt(rand.Reader, teeEciesPubKey, plaintext, nil, nil)
		require.NoError(t, err)

		additionalVariableMessages = append(additionalVariableMessages, cipher)
		privKeys = append(privKeys, privKey)
	}

	for i, privKey := range adminsPrivKeys {
		address := crypto.PubkeyToAddress(privKey.PublicKey)
		_, check := adminAndProvider[address]
		if check {
			continue
		}

		keySplit, err := backup.DecryptSplit(walletBackup.AdminEncryptedParts.Splits[i], privKey)
		require.NoError(t, err)

		plaintext, err := json.Marshal(keySplit)
		require.NoError(t, err)

		cipher, err := ecies.Encrypt(rand.Reader, teeEciesPubKey, plaintext, nil, nil)
		require.NoError(t, err)

		additionalVariableMessages = append(additionalVariableMessages, cipher)
		privKeys = append(privKeys, privKey)
	}

	action := testutils.BuildMockInstructionAction(
		t, op.Wallet, op.KeyDataProviderRestore, originalMessageEncoded, privKeys, teeID,
		rewardEpochID, additionalFixedMessage, additionalVariableMessages, adminAddresses, adminsThreshold,
		types.Threshold, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	response := <-actionResponseChan
	require.Equal(t, uint8(1), response.Result.Status)
	err = utils.VerifySignature(response.Result.Hash(), response.Signature, teeID)
	require.NoError(t, err)

	walletExistenceProof, err := wallets.ExtractKeyExistence(response.Result.Data, teeID)
	require.NoError(t, err)

	// check that commonwallet is actually on the tee
	commonwallet, err := wStorage.Get(wallets.KeyIDPair{WalletID: walletID, KeyID: keyID})
	require.NoError(t, err)
	require.Equal(t, walletID[:], commonwallet.WalletID[:])
	require.Equal(t, keyID, commonwallet.KeyID)

	// generate action sent when voting closed
	action = testutils.BuildMockInstructionAction(
		t, op.Wallet, op.KeyDataProviderRestore, originalMessageEncoded, privKeys, teeID,
		rewardEpochID, additionalFixedMessage, additionalVariableMessages, adminAddresses, adminsThreshold,
		types.End, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	response = <-actionResponseChan
	require.Equal(t, uint8(1), response.Result.Status)
	err = utils.VerifySignature(response.Result.Hash(), response.Signature, teeID)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(response.Result.Data, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeID)
	require.NoError(t, err)

	return walletExistenceProof
}

func getTeeAttestation(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	teeID common.Address,
	privKeys []*ecdsa.PrivateKey,
	rewardEpochId uint32,
) {
	t.Helper()

	challenge, err := random.Hash()
	require.NoError(t, err)

	originalMessage := verification.IVerificationTeeAttestation{
		Challenge: challenge,
		TeeMachine: verification.IMachineManagerTeeMachineWithAttestationData{
			TeeId:        teeID,
			InitialTeeId: teeID,
			Url:          "bla",
			CodeHash:     [32]byte{},
			Platform:     [32]byte{},
		},
	}

	originalMessageEncoded, err := abi.Arguments{verification.MessageArguments[op.TEEAttestation]}.Pack(originalMessage)
	require.NoError(t, err)

	// generate action sent when threshold reached
	action := testutils.BuildMockInstructionAction(
		t, op.Reg, op.TEEAttestation, originalMessageEncoded, privKeys, teeID, rewardEpochId, nil, nil, nil, 0, types.Threshold, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
	err = utils.VerifySignature(actionResponse.Result.Hash(), actionResponse.Signature, teeID)
	require.NoError(t, err)

	var teeInfoResponse types.TeeInfoResponse
	err = json.Unmarshal(actionResponse.Result.Data, &teeInfoResponse)
	require.NoError(t, err)

	teePubKey, err := types.ParsePubKey(teeInfoResponse.TeeInfo.PublicKey)
	require.NoError(t, err)

	receivedTeeID := crypto.PubkeyToAddress(*teePubKey)
	require.Equal(t, receivedTeeID, teeID)

	// generate action sent when voting closed
	action = testutils.BuildMockInstructionAction(
		t, op.Reg, op.TEEAttestation, originalMessageEncoded, privKeys, teeID, rewardEpochId, nil, nil, nil, 0, types.End, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	actionResponse = <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
	err = utils.VerifySignature(actionResponse.Result.Hash(), actionResponse.Signature, teeID)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(actionResponse.Result.Data, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeID)
	require.NoError(t, err)
}

func fdcProve(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	teeID common.Address,
	providerPrivKeys, cosignerPrivKeys []*ecdsa.PrivateKey,
	rewardEpochID uint32,
) {
	t.Helper()

	cosignerAddresses := make([]common.Address, len(cosignerPrivKeys))
	cosignerAndProvider := make(map[common.Address]bool)
	for j, cosignerPrivKey := range cosignerPrivKeys {
		cosignerAddresses[j] = crypto.PubkeyToAddress(cosignerPrivKey.PublicKey)
		for _, providerPrivKey := range providerPrivKeys {
			if cosignerAddresses[j] == crypto.PubkeyToAddress(providerPrivKey.PublicKey) {
				cosignerAndProvider[cosignerAddresses[j]] = true
			}
		}
	}
	cosignersThreshold := uint64(len(cosignerAddresses) / 2)
	originalMessage := fdc2.IFdc2HubFdc2AttestationRequest{
		Header: fdc2.IFdc2HubFdc2RequestHeader{
			AttestationType: [32]byte{},
			SourceId:        common.Hash{},
			ThresholdBIPS:   6000,
		},
		RequestBody: make([]byte, 10),
	}

	originalMessageEncoded, err := fdc.EncodeRequest(originalMessage)
	require.NoError(t, err)

	challenge, err := random.Hash()
	require.NoError(t, err)

	additionalFixedMessage := verification.IVerificationTeeAttestation{
		TeeMachine: verification.IMachineManagerTeeMachineWithAttestationData{
			TeeId:        teeID,
			InitialTeeId: common.Address{},
			Url:          "blabla",
			CodeHash:     [32]byte{},
			Platform:     [32]byte{},
		},
		Challenge: challenge,
	}

	additionalFixedMessageEncoded, err := types.EncodeTeeAttestationRequest(&additionalFixedMessage)
	require.NoError(t, err)

	timestamp := uint64(time.Now().Unix())
	fdcMsgHash, msgHash, _, _, err := fdc.HashMessage(originalMessage, additionalFixedMessageEncoded, cosignerAddresses, cosignersThreshold, timestamp)
	require.NoError(t, err)

	variableMessages := make([][]byte, 0, len(providerPrivKeys)+len(cosignerPrivKeys))
	privKeys := make([]*ecdsa.PrivateKey, 0, len(providerPrivKeys)+len(cosignerPrivKeys))
	for _, privKey := range providerPrivKeys {
		variableMessage, err := utils.Sign(fdcMsgHash[:], privKey)
		require.NoError(t, err)

		variableMessages = append(variableMessages, variableMessage)
		privKeys = append(privKeys, privKey)
	}
	for _, privKey := range cosignerPrivKeys {
		if _, check := cosignerAndProvider[crypto.PubkeyToAddress(privKey.PublicKey)]; check {
			continue
		}
		variableMessage, err := utils.Sign(fdcMsgHash[:], privKey)
		require.NoError(t, err)

		variableMessages = append(variableMessages, variableMessage)
		privKeys = append(privKeys, privKey)
	}

	action := testutils.BuildMockInstructionAction(
		t, op.FDC2, op.Prove, originalMessageEncoded, privKeys, teeID, rewardEpochID,
		additionalFixedMessageEncoded, variableMessages, cosignerAddresses, cosignersThreshold,
		types.Threshold, timestamp,
	)
	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
	err = utils.VerifySignature(actionResponse.Result.Hash(), actionResponse.Signature, teeID)
	require.NoError(t, err)

	var fdcResponse fdc.ProveResponse
	err = json.Unmarshal(actionResponse.Result.Data, &fdcResponse)
	require.NoError(t, err)

	err = utils.VerifySignature(msgHash.Bytes(), fdcResponse.TEESignature, teeID)
	require.NoError(t, err)

	require.Equal(t, len(fdcResponse.CosignerSignatures), len(cosignerPrivKeys))
	for _, signature := range fdcResponse.CosignerSignatures {
		_, err = utils.CheckSignature(fdcMsgHash.Bytes(), signature, cosignerAddresses)
		require.NoError(t, err)
	}
	require.Equal(t, fdcResponse.ResponseBody, additionalFixedMessageEncoded)

	// Decode and verify the encoded data-provider signatures blob.
	providerAddresses := make([]common.Address, len(providerPrivKeys))
	for i, k := range providerPrivKeys {
		providerAddresses[i] = crypto.PubkeyToAddress(k.PublicKey)
	}
	testutils.VerifyEncodedDataProviderSignatures(
		t, fdcResponse.DataProviderSignatures, fdcMsgHash, providerAddresses, len(providerPrivKeys),
	)

	// generate action sent when voting closed
	action = testutils.BuildMockInstructionAction(
		t, op.FDC2, op.Prove, originalMessageEncoded, privKeys, teeID, rewardEpochID,
		additionalFixedMessageEncoded, variableMessages, cosignerAddresses, cosignersThreshold,
		types.End, timestamp,
	)
	actionInfoChan <- action

	actionResponse = <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
	err = utils.VerifySignature(actionResponse.Result.Hash(), actionResponse.Signature, teeID)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(actionResponse.Result.Data, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeID)
	require.NoError(t, err)
}

func MockProxy(t *testing.T, proxyPort int, mainChan, readChan chan *types.Action, respChan chan *types.ActionResponse) {
	t.Helper()

	router := http.NewServeMux()

	router.HandleFunc("POST /queue/main", func(w http.ResponseWriter, r *http.Request) {
		var action types.Action
		select {
		case x := <-mainChan:
			action = *x
		default:
			action = types.Action{}
		}

		response, err := json.Marshal(action)
		require.NoError(t, err)

		_, err = w.Write(response)
		require.NoError(t, err)
	})

	router.HandleFunc("POST /queue/direct", func(w http.ResponseWriter, r *http.Request) {
		var action types.Action
		select {
		case x := <-readChan:
			action = *x
		default:
			action = types.Action{}
		}

		response, err := json.Marshal(action)
		require.NoError(t, err)

		_, err = w.Write(response)
		require.NoError(t, err)
	})

	router.HandleFunc("POST /queue/backup", func(w http.ResponseWriter, r *http.Request) {
		response, err := json.Marshal(types.Action{})
		require.NoError(t, err)

		_, err = w.Write(response)
		require.NoError(t, err)
	})

	router.HandleFunc("POST /result", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var actionResponse types.ActionResponse
		err = json.Unmarshal(body, &actionResponse)
		require.NoError(t, err)
		respChan <- &actionResponse
		err = r.Body.Close()
		require.NoError(t, err)
	})

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", proxyPort), router))
}
