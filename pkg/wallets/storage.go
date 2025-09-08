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

func InitializeStorage() *Storage {
	return &Storage{
		wallets:   make(map[KeyIDPair]*Wallet),
		permanent: make(map[KeyIDPair]*WalletStatus),
	}
}

func (s *Storage) Store(wallet *Wallet) error {
	idPair := KeyIDPair{WalletID: wallet.WalletID, KeyID: wallet.KeyID}
	walletCopied := CopyWallet(wallet)

	s.Lock()
	defer s.Unlock()

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

func (s *Storage) Remove(idPair KeyIDPair) {
	s.Lock()
	defer s.Unlock()
	delete(s.wallets, idPair)
}

var ErrWalletNonExistent = errors.New("wallet non-existent")

func (s *Storage) Get(idPair KeyIDPair) (*Wallet, error) {
	s.RLock()
	defer s.RUnlock()
	wallet, ok := s.wallets[idPair]
	if !ok || wallet == nil {
		return nil, ErrWalletNonExistent
	}
	walletCopy := CopyWallet(wallet)

	return walletCopy, nil
}

func (s *Storage) GetWallets() []*Wallet {
	wallets := make([]*Wallet, len(s.wallets))
	i := 0
	s.RLock()
	defer s.RUnlock()
	for _, wallet := range s.wallets {
		wallets[i] = CopyWallet(wallet)
		i++
	}

	return wallets
}

func (s *Storage) WalletExists(idPair KeyIDPair) bool {
	s.RLock()
	defer s.RUnlock()
	_, ok := s.wallets[idPair]
	return ok
}

func (s *Storage) CheckNonce(idPair KeyIDPair, nonce uint64) error {
	s.RLock()
	defer s.RUnlock()
	walletStatus, ok := s.permanent[idPair]
	if !ok {
		return nil
	}
	if nonce <= walletStatus.Nonce {
		return errors.New("nonce too small")
	}

	return nil
}

func (s *Storage) Nonce(idPair KeyIDPair) (uint64, error) {
	s.RLock()
	defer s.RUnlock()
	walletStatus, ok := s.permanent[idPair]
	if !ok {
		return 0, errors.New("no wallet nonce")
	}

	return walletStatus.Nonce, nil
}

func (s *Storage) UpdateNonce(idPair KeyIDPair, nonce uint64) {
	s.Lock()
	defer s.Unlock()
	if walletStatus, ok := s.permanent[idPair]; ok {
		walletStatus.Nonce = nonce
	}
}

func (s *Storage) DestroyState() {
	s.Lock()
	defer s.Unlock()

	s.wallets = make(map[KeyIDPair]*Wallet)
	s.permanent = make(map[KeyIDPair]*WalletStatus)
}
