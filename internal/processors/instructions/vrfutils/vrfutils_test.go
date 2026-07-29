package vrfutils

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	vrfstruct "github.com/flare-foundation/go-flare-common/pkg/tee/structs/vrf"
	"github.com/flare-foundation/tee-node/internal/testutils"
	walletstorage "github.com/flare-foundation/tee-node/internal/wallets"
	"github.com/flare-foundation/tee-node/pkg/types"
	wallets "github.com/flare-foundation/tee-node/pkg/wallets"
	"github.com/flare-foundation/tee-node/pkg/wallets/vrf"
	"github.com/stretchr/testify/require"
)

type proveRandomnessSetup struct {
	processor Processor
	wStorage  *walletstorage.Storage
	walletID  common.Hash
	keyID     uint64
}

func setupProveRandomnessTest(t *testing.T) *proveRandomnessSetup {
	t.Helper()

	testNode, pStorage, wStorage := testutils.Setup(t)
	testutils.GenerateAndSetInitialPolicy(t, pStorage, 10, 12345, 1)

	sk, err := crypto.GenerateKey()
	require.NoError(t, err)

	walletID := common.HexToHash("0xdecaf")
	keyID := uint64(4)

	wStorage.Lock()
	err = wStorage.Store(&wallets.Wallet{
		WalletID:    walletID,
		KeyID:       keyID,
		PrivateKey:  common.BigToHash(sk.D).Bytes(),
		KeyType:     wallets.EVMType,
		SigningAlgo: wallets.VRFAlgo,
		Status:      &wallets.WalletStatus{},
	})
	wStorage.Unlock()
	require.NoError(t, err)

	return &proveRandomnessSetup{
		processor: NewProcessor(testNode, wStorage),
		wStorage:  wStorage,
		walletID:  walletID,
		keyID:     keyID,
	}
}

func buildRequestInstruction(t *testing.T, walletID common.Hash, keyID uint64, nonce []byte) *instruction.DataFixed {
	t.Helper()

	enc, err := abi.Arguments{vrfstruct.MessageArguments[op.VRF]}.Pack(vrfstruct.IVrfVrfInstructionMessage{
		WalletId: [32]byte(walletID),
		KeyId:    keyID,
		Nonce:    nonce,
	})
	require.NoError(t, err)

	return &instruction.DataFixed{
		OriginalMessage: enc,
	}
}

func randomNonce(t *testing.T) []byte {
	t.Helper()

	b := make([]byte, 32)
	_, err := rand.Read(b)
	require.NoError(t, err)

	return b
}

func TestProveRandomness(t *testing.T) {
	setup := setupProveRandomnessTest(t)
	nonce := randomNonce(t)
	data := buildRequestInstruction(t, setup.walletID, setup.keyID, nonce)

	resBytes, _, err := setup.processor.ProveRandomness(context.Background(), types.Threshold, data, nil, nil, nil)
	require.NoError(t, err)

	var resp types.ProveRandomnessResponse
	err = json.Unmarshal(resBytes, &resp)
	require.NoError(t, err)

	require.Equal(t, setup.walletID, resp.WalletID)
	require.Equal(t, setup.keyID, resp.KeyID)
	require.Equal(t, nonce, []byte(resp.Nonce))

	stored, err := setup.wStorage.Get(wallets.KeyIDPair{WalletID: setup.walletID, KeyID: setup.keyID})
	require.NoError(t, err)

	pub := wallets.ToECDSAUnsafe(stored.PrivateKey).PublicKey
	err = vrf.VerifyRandomness(&resp.Proof, &pub, nonce)
	require.NoError(t, err)

	randomness, err := resp.Proof.RandomnessFromProof()
	require.NoError(t, err)
	require.NotEqual(t, common.Hash{}, randomness)
}

func TestProveRandomnessWalletNotFound(t *testing.T) {
	setup := setupProveRandomnessTest(t)
	data := buildRequestInstruction(t, common.HexToHash("0x123"), setup.keyID, randomNonce(t))

	_, _, err := setup.processor.ProveRandomness(context.Background(), types.Threshold, data, nil, nil, nil)
	require.Error(t, err)
	require.Equal(t, walletstorage.ErrWalletNonExistent, err)
}

func TestProveRandomnessInvalidRequestEncoding(t *testing.T) {
	setup := setupProveRandomnessTest(t)
	data := &instruction.DataFixed{
		OriginalMessage: []byte{0x01, 0x02, 0x03},
	}

	_, _, err := setup.processor.ProveRandomness(context.Background(), types.Threshold, data, nil, nil, nil)
	require.Error(t, err)
}

func TestProveRandomnessEmptyNonce(t *testing.T) {
	setup := setupProveRandomnessTest(t)
	data := buildRequestInstruction(t, setup.walletID, setup.keyID, []byte{})

	_, _, err := setup.processor.ProveRandomness(context.Background(), types.Threshold, data, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nonce is empty")
}

func TestProveRandomnessUnsupportedSigningAlgo(t *testing.T) {
	setup := setupProveRandomnessTest(t)
	customWalletID := common.HexToHash("0x4242")
	customKeyID := uint64(99)
	sk, err := crypto.GenerateKey()
	require.NoError(t, err)

	setup.wStorage.Lock()
	err = setup.wStorage.Store(&wallets.Wallet{
		WalletID:    customWalletID,
		KeyID:       customKeyID,
		PrivateKey:  common.BigToHash(sk.D).Bytes(),
		KeyType:     wallets.XRPType,
		SigningAlgo: common.HexToHash("0xdead"),
		Status:      &wallets.WalletStatus{},
	})
	setup.wStorage.Unlock()
	require.NoError(t, err)

	data := buildRequestInstruction(t, customWalletID, customKeyID, randomNonce(t))
	_, _, err = setup.processor.ProveRandomness(context.Background(), types.Threshold, data, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not support vrf")
}
