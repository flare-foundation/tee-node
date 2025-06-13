package wallets

import (
	"sync"

	"github.com/pkg/errors"
)

var Storage = InitWalletsStorage()

type WalletsStorage struct {
	// if a wallet exists, its Status attribute should
	// point to the same struct as is saved in permanent
	wallets   map[WalletKeyIdPair]*Wallet
	permanent map[WalletKeyIdPair]*WalletStatus

	sync.RWMutex
}

func InitWalletsStorage() *WalletsStorage {
	return &WalletsStorage{
		wallets:   make(map[WalletKeyIdPair]*Wallet),
		permanent: make(map[WalletKeyIdPair]*WalletStatus),
	}
}

func (walletsStorage *WalletsStorage) StoreWallet(wallet *Wallet) error {
	idPair := WalletKeyIdPair{WalletId: wallet.WalletId, KeyId: wallet.KeyId}
	walletCopied := CopyWallet(wallet)

	if _, ok := walletsStorage.wallets[idPair]; ok {
		return errors.New("wallet with given walletId and keyId already exists")
	}

	if walletStatus, ok := walletsStorage.permanent[idPair]; ok {
		walletCopied.Status = walletStatus
	} else {
		walletsStorage.permanent[idPair] = walletCopied.Status
	}

	walletsStorage.wallets[idPair] = walletCopied

	return nil
}

func (walletsStorage *WalletsStorage) RemoveWallet(idPair WalletKeyIdPair) {
	delete(walletsStorage.wallets, idPair)
}

func (walletsStorage *WalletsStorage) GetWallet(idPair WalletKeyIdPair) (*Wallet, error) {
	wallet, ok := walletsStorage.wallets[idPair]
	if !ok || wallet == nil {
		return nil, errors.New("wallet non-existent")
	}
	walletCopy := CopyWallet(wallet)

	return walletCopy, nil
}

func (walletsStorage *WalletsStorage) WalletExists(idPair WalletKeyIdPair) bool {
	_, ok := walletsStorage.wallets[idPair]
	return ok
}

func (walletsStorage *WalletsStorage) CheckNonce(idPair WalletKeyIdPair, nonce uint64) error {
	walletStatus, ok := walletsStorage.permanent[idPair]
	if !ok {
		return nil
	}
	if nonce <= walletStatus.Nonce {
		return errors.New("nonce too small")
	}

	return nil
}

func (walletsStorage *WalletsStorage) UpdateNonce(idPair WalletKeyIdPair, nonce uint64) {
	if walletStatus, ok := walletsStorage.permanent[idPair]; ok {
		walletStatus.Nonce = nonce
	}
}

func (walletsStorage *WalletsStorage) DestroyState() {
	walletsStorage.Lock()
	defer walletsStorage.Unlock()

	walletsStorage.wallets = make(map[WalletKeyIdPair]*Wallet)
	walletsStorage.permanent = make(map[WalletKeyIdPair]*WalletStatus)
}
