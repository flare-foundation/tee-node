package wallets

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestInitializeStorage(t *testing.T) {
	s := InitializeStorage()
	require.NotNil(t, s)
	require.NotNil(t, s.wallets)
	require.NotNil(t, s.permanent)
}

func createTestWalletForStorage() *Wallet {
	return &Wallet{
		WalletID:    common.HexToHash("0x6b"),
		KeyID:       777,
		PrivateKey:  []byte{1, 2, 3, 4, 5},
		KeyType:     XRPType,
		SigningAlgo: XRPAlgo,
		Status:      &WalletStatus{Nonce: 1, StatusCode: 2, PausingNonce: common.HexToHash("0xaa")},
	}
}

func TestStoreAndGetWallet(t *testing.T) {
	s := InitializeStorage()
	w := createTestWalletForStorage()
	idPair := KeyIDPair{WalletID: w.WalletID, KeyID: w.KeyID}

	require.False(t, s.WalletExists(idPair))

	err := s.Store(w)
	require.NoError(t, err)
	require.True(t, s.WalletExists(idPair))

	ret, err := s.Get(idPair)
	require.NoError(t, err)
	require.NotNil(t, ret)
	require.Equal(t, w.WalletID, ret.WalletID)
	require.Equal(t, w.KeyID, ret.KeyID)
	require.Equal(t, w.Status.Nonce, ret.Status.Nonce)
}

func TestStoreDuplicateWallet(t *testing.T) {
	s := InitializeStorage()
	w := createTestWalletForStorage()

	err := s.Store(w)
	require.NoError(t, err)

	err = s.Store(w)
	require.Error(t, err)
	require.Contains(t, err.Error(), "wallet with given walletID and keyID already exists")
}

func TestRemoveWallet(t *testing.T) {
	s := InitializeStorage()
	w := createTestWalletForStorage()
	idPair := KeyIDPair{WalletID: w.WalletID, KeyID: w.KeyID}

	_ = s.Store(w)
	require.True(t, s.WalletExists(idPair))

	s.Remove(idPair)
	require.False(t, s.WalletExists(idPair))
}

func TestGet_NonExistentWallet(t *testing.T) {
	s := InitializeStorage()
	idPair := KeyIDPair{WalletID: common.HexToHash("0xFAFA"), KeyID: 4321}
	_, err := s.Get(idPair)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrWalletNonExistent))
}

func TestGetWallets(t *testing.T) {
	s := InitializeStorage()
	w1 := createTestWalletForStorage()
	w2 := createTestWalletForStorage()
	w2.WalletID = common.HexToHash("0x78")
	w2.KeyID = 888

	require.NoError(t, s.Store(w1))
	require.NoError(t, s.Store(w2))

	wallets := s.GetWallets()
	// Both w1 and w2 should be stored
	require.Len(t, wallets, 2)

	// All returned wallets should be copies, mutations don't affect storage
	original, _ := s.Get(KeyIDPair{WalletID: w1.WalletID, KeyID: w1.KeyID})
	require.Equal(t, w1.WalletID, original.WalletID)
	wallets[0].WalletID = common.HexToHash("0x999")
	original2, _ := s.Get(KeyIDPair{WalletID: w1.WalletID, KeyID: w1.KeyID})
	require.Equal(t, w1.WalletID, original2.WalletID)
}

func TestWalletExists(t *testing.T) {
	s := InitializeStorage()
	w := createTestWalletForStorage()
	idPair := KeyIDPair{WalletID: w.WalletID, KeyID: w.KeyID}

	require.False(t, s.WalletExists(idPair))
	_ = s.Store(w)
	require.True(t, s.WalletExists(idPair))
}

func TestCheckNonce(t *testing.T) {
	s := InitializeStorage()
	w := createTestWalletForStorage()
	idPair := KeyIDPair{WalletID: w.WalletID, KeyID: w.KeyID}
	_ = s.Store(w)

	// nonce greater than current is allowed
	err := s.CheckNonce(idPair, w.Status.Nonce+1)
	require.NoError(t, err)

	// nonce equal to current should error
	err = s.CheckNonce(idPair, w.Status.Nonce)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nonce too small")

	// nonce less than current should error
	err = s.CheckNonce(idPair, w.Status.Nonce-1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nonce too small")

	// for non-existent wallet, should allow any nonce
	missingPair := KeyIDPair{WalletID: common.HexToHash("0x1234"), KeyID: 99999}
	err = s.CheckNonce(missingPair, 1)
	require.NoError(t, err)
}

func TestNonceAndUpdateNonce(t *testing.T) {
	s := InitializeStorage()
	w := createTestWalletForStorage()
	idPair := KeyIDPair{WalletID: w.WalletID, KeyID: w.KeyID}
	_ = s.Store(w)

	got, err := s.Nonce(idPair)
	require.NoError(t, err)
	require.Equal(t, w.Status.Nonce, got)

	newNonce := uint64(888)
	s.UpdateNonce(idPair, newNonce)
	got2, err := s.Nonce(idPair)
	require.NoError(t, err)
	require.Equal(t, newNonce, got2)

	// Nonce for non-existent wallet errors
	missingPair := KeyIDPair{WalletID: common.HexToHash("0xabcd"), KeyID: 5656}
	_, err = s.Nonce(missingPair)
	require.Error(t, err)
	require.Equal(t, "no wallet nonce", err.Error())
}

func TestStorePreservesStatusPointer(t *testing.T) {
	s := InitializeStorage()
	w := createTestWalletForStorage()
	idPair := KeyIDPair{WalletID: w.WalletID, KeyID: w.KeyID}

	_ = s.Store(w)
	// Mutate nonce through UpdateNonce, should reflect in .Get()
	s.UpdateNonce(idPair, 555)
	got, err := s.Get(idPair)
	require.NoError(t, err)
	require.Equal(t, uint64(555), got.Status.Nonce)
}
