package getutils

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/policy"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
	pwallets "github.com/flare-foundation/tee-node/pkg/wallets"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyInfo(t *testing.T) {
	testNode, pStorage, wStorage := testutils.Setup(t)

	numVoters, randSeed, epochID := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(t, pStorage, numVoters, randSeed, epochID)

	mockWalletID1 := common.HexToHash("0xabcdef")
	mockKeyID1 := uint64(1)
	testutils.CreateMockWallet(t, testNode, pStorage, wStorage, mockWalletID1, mockKeyID1, epochID, []*ecdsa.PrivateKey{privKeys[0]}, nil)

	mockWalletID2 := common.HexToHash("0xabcdefab")
	mockKeyID2 := uint64(2)
	testutils.CreateMockWallet(t, testNode, pStorage, wStorage, mockWalletID2, mockKeyID2, epochID, []*ecdsa.PrivateKey{privKeys[1]}, nil)

	proc := NewProcessor(testNode, pStorage, wStorage)

	walletsPackage, err := proc.KeysInfo(nil)
	require.NoError(t, err)

	var infos []types.KeyInfo
	err = json.Unmarshal(walletsPackage, &infos)
	require.NoError(t, err)

	require.ElementsMatch(t, []types.KeyInfo{
		{WalletID: mockWalletID1, KeyID: mockKeyID1, Nonce: 0},
		{WalletID: mockWalletID2, KeyID: mockKeyID2, Nonce: 0},
	}, infos)
}

func TestKeysInfoSize(t *testing.T) {
	testNode, pStorage, wStorage := testutils.Setup(t)

	const n = settings.MaxWallets
	wStorage.Lock()
	for i := range uint64(n) {
		w := &pwallets.Wallet{
			WalletID: common.BigToHash(new(big.Int).SetUint64(i + 1)),
			KeyID:    i,
			Status:   &pwallets.WalletStatus{},
		}
		require.NoError(t, wStorage.Store(w))
	}
	wStorage.Unlock()

	proc := NewProcessor(testNode, pStorage, wStorage)

	res, err := proc.KeysInfo(nil)
	require.NoError(t, err)

	var infos []types.KeyInfo
	require.NoError(t, json.Unmarshal(res, &infos))
	require.Len(t, infos, n)

	require.Less(t, len(res), 25*1024*1024, "KEY_INFO response for %d wallets is %d bytes, exceeds 25 MiB", n, len(res))
}

func TestKeysProofSize100(t *testing.T) {
	testNode, pStorage, wStorage := testutils.Setup(t)

	const n = 100

	sk, err := crypto.GenerateKey()
	require.NoError(t, err)

	adminKeys := make([]*ecdsa.PublicKey, 10)
	for j := range adminKeys {
		k, err := crypto.GenerateKey()
		require.NoError(t, err)
		adminKeys[j] = &k.PublicKey
	}

	cosigners := make([]common.Address, 10)
	for j := range cosigners {
		k, err := crypto.GenerateKey()
		require.NoError(t, err)
		cosigners[j] = crypto.PubkeyToAddress(k.PublicKey)
	}

	requested := make([]pwallets.KeyIDPair, 0, n)
	wStorage.Lock()
	for i := range uint64(n) {
		walletID := common.BigToHash(new(big.Int).SetUint64(i + 1))
		w := &pwallets.Wallet{
			WalletID:           walletID,
			KeyID:              i,
			PrivateKey:         common.BigToHash(sk.D).Bytes(),
			KeyType:            pwallets.XRPType,
			SigningAlgo:        pwallets.XRPSignAlgo,
			AdminPublicKeys:    adminKeys,
			AdminsThreshold:    5,
			Cosigners:          cosigners,
			CosignersThreshold: 5,
			Status:             &pwallets.WalletStatus{},
		}
		require.NoError(t, wStorage.Store(w))
		requested = append(requested, pwallets.KeyIDPair{WalletID: walletID, KeyID: i})
	}
	wStorage.Unlock()

	proc := NewProcessor(testNode, pStorage, wStorage)

	msg, err := json.Marshal(requested)
	require.NoError(t, err)

	res, err := proc.KeysProof(&types.DirectInstruction{Message: msg})
	require.NoError(t, err)

	var proofs []pwallets.SignedKeyExistenceProof
	require.NoError(t, json.Unmarshal(res, &proofs))
	require.Len(t, proofs, n)

	require.Less(t, len(res), 1024*1024, "KEY_PROOF response for %d keys should be under 1 MiB, got %d bytes", n, len(res))
}

func TestKeysProof(t *testing.T) {
	t.Run("KeysProof success", func(t *testing.T) {
		testNode, pStorage, wStorage := testutils.Setup(t)

		numVoters, randSeed, epochID := 100, int64(12345), uint32(1)
		_, _, privKeys := testutils.GenerateAndSetInitialPolicy(t, pStorage, numVoters, randSeed, epochID)

		mockWalletID1 := common.HexToHash("0xabcdef")
		mockKeyID1 := uint64(1)
		walletProofs := make(map[common.Hash]wallet.ITeeWalletKeyManagerKeyExistence)
		walletProofs[mockWalletID1] = testutils.CreateMockWallet(t, testNode, pStorage, wStorage, mockWalletID1, mockKeyID1, epochID, []*ecdsa.PrivateKey{privKeys[0]}, nil)

		mockWalletID2 := common.HexToHash("0xabcdefab")
		mockKeyID2 := uint64(2)
		walletProofs[mockWalletID2] = testutils.CreateMockWallet(t, testNode, pStorage, wStorage, mockWalletID2, mockKeyID2, epochID, []*ecdsa.PrivateKey{privKeys[1]}, nil)

		proc := NewProcessor(testNode, pStorage, wStorage)

		requested := []pwallets.KeyIDPair{
			{WalletID: mockWalletID1, KeyID: mockKeyID1},
			{WalletID: mockWalletID2, KeyID: mockKeyID2},
		}
		msg, err := json.Marshal(requested)
		require.NoError(t, err)

		res, err := proc.KeysProof(&types.DirectInstruction{Message: msg})
		require.NoError(t, err)

		var existenceProofs []pwallets.SignedKeyExistenceProof
		err = json.Unmarshal(res, &existenceProofs)
		require.NoError(t, err)

		require.Len(t, existenceProofs, len(requested))

		for i, proof := range existenceProofs {
			err = utils.VerifySignature(crypto.Keccak256(proof.KeyExistence), proof.Signature, testNode.TeeID())
			require.NoError(t, err)

			walletExistenceProof, err := structs.Decode[wallet.ITeeWalletKeyManagerKeyExistence](wallet.KeyExistenceStructArg, proof.KeyExistence)
			require.NoError(t, err)

			require.Equal(t, requested[i].WalletID, common.Hash(walletExistenceProof.WalletId))
			require.Equal(t, walletProofs[common.Hash(walletExistenceProof.WalletId)], walletExistenceProof)
		}
	})

	t.Run("KeysProof empty request returns empty list", func(t *testing.T) {
		testNode, pStorage, wStorage := testutils.Setup(t)
		proc := NewProcessor(testNode, pStorage, wStorage)

		msg, err := json.Marshal([]pwallets.KeyIDPair{})
		require.NoError(t, err)

		res, err := proc.KeysProof(&types.DirectInstruction{Message: msg})
		require.NoError(t, err)

		var existenceProofs []pwallets.SignedKeyExistenceProof
		require.NoError(t, json.Unmarshal(res, &existenceProofs))
		require.Empty(t, existenceProofs)
	})

	t.Run("KeysProof malformed message", func(t *testing.T) {
		testNode, pStorage, wStorage := testutils.Setup(t)
		proc := NewProcessor(testNode, pStorage, wStorage)

		_, err := proc.KeysProof(&types.DirectInstruction{Message: []byte("not-json")})
		require.Error(t, err)
	})

	t.Run("KeysProof unknown wallet errors", func(t *testing.T) {
		testNode, pStorage, wStorage := testutils.Setup(t)
		proc := NewProcessor(testNode, pStorage, wStorage)

		msg, err := json.Marshal([]pwallets.KeyIDPair{{WalletID: common.HexToHash("0xdead"), KeyID: 0}})
		require.NoError(t, err)

		_, err = proc.KeysProof(&types.DirectInstruction{Message: msg})
		require.Error(t, err)
	})
}

func TestTEEInfo(t *testing.T) {
	t.Run("TEEInfo success", func(t *testing.T) {
		testNode, pStorage, wStorage := testutils.Setup(t)
		proc := NewProcessor(testNode, pStorage, wStorage)

		challenge := common.HexToHash("0xa")
		req := types.TeeInfoRequest{
			Challenge: [32]byte(challenge),
		}
		message, err := json.Marshal(req)
		require.NoError(t, err)

		result, err := proc.TEEInfo(&types.DirectInstruction{Message: message})
		require.NoError(t, err)
		require.NotNil(t, result)

		var teeInfo = new(types.TeeInfoResponse)
		require.NoError(t, json.NewDecoder(bytes.NewReader(result)).Decode(&teeInfo))

		require.Equal(t, teeInfo.TeeInfo.Challenge, challenge)
		require.Equal(t, teeInfo.TeeInfo.PublicKey, testNode.Info().PublicKey)
		require.Equal(t, teeInfo.TeeInfo.InitialSigningPolicyID, uint32(0))
		require.Equal(t, teeInfo.TeeInfo.LastSigningPolicyID, uint32(0))
		require.Equal(t, teeInfo.TeeInfo.TeeTimestamp, uint64(time.Now().Unix()))

		// MachineData
		require.Equal(t, teeInfo.MachineData.PublicKey, testNode.Info().PublicKey)
		require.Equal(t, teeInfo.MachineData.InitialOwner, testNode.Info().InitialOwner)

		// Signature
		mdHash, err := teeInfo.MachineData.Hash()
		require.NoError(t, err)
		err = utils.VerifySignature(mdHash[:], teeInfo.DataSignature, testNode.Info().TeeID)
		require.NoError(t, err)
	})

	t.Run("TEEInfo unmarshal error", func(t *testing.T) {
		_, pStorage, wStorage := testutils.Setup(t)
		proc := NewProcessor(nil, pStorage, wStorage)

		i := &types.DirectInstruction{Message: []byte("invalid")}
		res, err := proc.TEEInfo(i)
		require.Error(t, err)
		require.Nil(t, res)
	})
}

func TestTEEBackup(t *testing.T) {
	t.Run("TEEBackup success", func(t *testing.T) {
		testNode, pStorage, wStorage := testutils.Setup(t)
		numVoters, randSeed, epochID := 3, int64(99991), uint32(2)
		_, _, privKeys := testutils.GenerateAndSetInitialPolicy(t, pStorage, numVoters, randSeed, epochID)
		walletID := common.HexToHash("0xaaaaa")
		keyID := uint64(111)
		testutils.CreateMockWallet(t, testNode, pStorage, wStorage, walletID, keyID, epochID, []*ecdsa.PrivateKey{privKeys[0]}, nil)

		proc := NewProcessor(testNode, pStorage, wStorage)
		idPair := pwallets.KeyIDPair{WalletID: walletID, KeyID: keyID}
		msg, err := json.Marshal(idPair)
		require.NoError(t, err)
		res, err := proc.TEEBackup(&types.DirectInstruction{Message: msg})
		require.NoError(t, err)
		require.NotNil(t, res)

		var outer pwallets.TEEBackupResponse
		require.NoError(t, json.Unmarshal(res, &outer))
		require.NotEmpty(t, outer.WalletBackup)
		require.Equal(t, outer.BackupID, outer.BackupID)
	})

	t.Run("TEEBackup should fail on malformed instruction", func(t *testing.T) {
		_, pStorage, wStorage := testutils.Setup(t)
		proc := NewProcessor(nil, pStorage, wStorage)
		i := &types.DirectInstruction{Message: []byte("bad")}
		_, err := proc.TEEBackup(i)
		require.Error(t, err)
	})

	t.Run("TEEBackup should fail on non-existent wallet", func(t *testing.T) {
		testNode, pStorage, wStorage := testutils.Setup(t)
		proc := NewProcessor(testNode, pStorage, wStorage)

		idPair := pwallets.KeyIDPair{WalletID: common.HexToHash("0xfffffff"), KeyID: 777}
		msg, _ := json.Marshal(idPair)
		i := &types.DirectInstruction{Message: msg}
		_, err := proc.TEEBackup(i)
		require.Error(t, err)
	})

	t.Run("TEEBackup should fail without initialized policy", func(t *testing.T) {
		testNode, _, wStorage := testutils.Setup(t)
		pStorage := policy.InitializeStorage()
		proc := NewProcessor(testNode, pStorage, wStorage)

		walletID := common.HexToHash("0x12345")
		keyID := uint64(9)

		adminPrivKey, err := crypto.GenerateKey()
		require.NoError(t, err)

		testutils.CreateMockWallet(t, testNode, pStorage, wStorage, walletID, keyID, 2, []*ecdsa.PrivateKey{adminPrivKey}, nil)
		idPair := pwallets.KeyIDPair{WalletID: walletID, KeyID: keyID}
		msg, _ := json.Marshal(idPair)
		i := &types.DirectInstruction{Message: msg}

		_, err = proc.TEEBackup(i)
		require.Error(t, err)
	})

	t.Run("TEEBackup signing fails when Sign returns an error", func(t *testing.T) {
		testNode, pStorage, wStorage := testutils.Setup(t)
		numVoters, randSeed, epochID := 1, int64(3232), uint32(3)
		_, _, privKeys := testutils.GenerateAndSetInitialPolicy(t, pStorage, numVoters, randSeed, epochID)
		walletID := common.HexToHash("0x7744")
		keyID := uint64(123)
		testutils.CreateMockWallet(t, testNode, pStorage, wStorage, walletID, keyID, epochID, []*ecdsa.PrivateKey{privKeys[0]}, nil)

		proc := NewProcessor(struct {
			node.InformerAndSigner
		}{testNode}, pStorage, wStorage)

		// Simulate failing Sign operation
		proc.InformerAndSigner = signerMock{testNode}

		idPair := pwallets.KeyIDPair{WalletID: walletID, KeyID: keyID}
		msg, _ := json.Marshal(idPair)
		i := &types.DirectInstruction{Message: msg}
		_, err := proc.TEEBackup(i)
		require.Error(t, err)
	})
}

type signerMock struct{ node.InformerAndSigner }

func (b signerMock) Sign(_ []byte) ([]byte, error) { return nil, assert.AnError }
