package wallets

import (
	"errors"
	"sync"
)

type Storage struct {
	// if a wallet exists, its Status attribute should
	// point to the same struct as is saved in permanent
	wallets   map[KeyIDPair]*Wallet
	permanent map[KeyIDPair]*WalletStatus

	sync.RWMutex
}

// InitializeStorage returns an empty wallet storage instance.
func InitializeStorage() *Storage {
	return &Storage{
		wallets:   make(map[KeyIDPair]*Wallet),
		permanent: make(map[KeyIDPair]*WalletStatus),
	}
}

// Store adds the wallet to storage while preserving status state.
//
// s.RWMutex Lock should be used when calling this method.
func (s *Storage) Store(wallet *Wallet) error {
	idPair := KeyIDPair{WalletID: wallet.WalletID, KeyID: wallet.KeyID}
	walletCopied := wallet.Copy()

	if _, ok := s.wallets[idPair]; ok {
		return errors.New("wallet with given walletID and keyID already exists")
	}

	if walletStatus, ok := s.permanent[idPair]; ok {
		walletCopied.Status = walletStatus
	} else {
		s.permanent[idPair] = walletCopied.Status
	}

	s.wallets[idPair] = walletCopied

	return nil
}

// Remove deletes the wallet entry for the given identifier pair.
//
// s.RWMutex Lock should be used when calling this method.
func (s *Storage) Remove(idPair KeyIDPair) bool {
	_, exists := s.wallets[idPair]
	delete(s.wallets, idPair)

	return exists
}

var ErrWalletNonExistent = errors.New("wallet non-existent")

// Get retrieves a copy of the wallet or returns ErrWalletNonExistent.
//
// s.RWMutex RLock should be used when calling this method.
func (s *Storage) Get(idPair KeyIDPair) (*Wallet, error) {
	wallet, ok := s.wallets[idPair]
	if !ok || wallet == nil {
		return nil, ErrWalletNonExistent
	}
	walletCopy := wallet.Copy()

	return walletCopy, nil
}

// GetWallets returns deep copies of all stored wallets.
//
// s.RWMutex RLock should be used when calling this method.
func (s *Storage) GetWallets() []*Wallet {
	wallets := make([]*Wallet, len(s.wallets))
	i := 0

	for _, wallet := range s.wallets {
		wallets[i] = wallet.Copy()
		i++
	}

	return wallets
}

// WalletExists reports whether the wallet is present in storage.
//
// s.RWMutex RLock should be used when calling this method.
func (s *Storage) WalletExists(idPair KeyIDPair) bool {
	_, ok := s.wallets[idPair]
	return ok
}

// WalletExistsPermanent reports whether the wallet is present in permanent storage.
//
// s.RWMutex RLock should be used when calling this method.
func (s *Storage) WalletExistsPermanent(idPair KeyIDPair) bool {
	_, ok := s.permanent[idPair]
	return ok
}

// CheckNonce ensures the provided nonce is newer than the stored one.
//
// s.RWMutex RLock should be used when calling this method.
func (s *Storage) CheckNonce(idPair KeyIDPair, nonce uint64) error {
	walletStatus, ok := s.permanent[idPair]
	if !ok {
		return errors.New("no permanent record of the wallet")
	}
	if nonce <= walletStatus.Nonce {
		return errors.New("nonce too small")
	}

	return nil
}

// Nonce returns the stored nonce for the wallet.
//
// s.RWMutex RLock should be used when calling this method.
func (s *Storage) Nonce(idPair KeyIDPair) (uint64, error) {
	walletStatus, ok := s.permanent[idPair]
	if !ok {
		return 0, errors.New("no wallet nonce")
	}

	return walletStatus.Nonce, nil
}

// UpdateNonce sets the wallet's nonce to the provided value.
//
// s.RWMutex Lock should be used when calling this method.
func (s *Storage) UpdateNonce(idPair KeyIDPair, nonce uint64) {
	if walletStatus, ok := s.permanent[idPair]; ok {
		walletStatus.Nonce = nonce
	}
}
