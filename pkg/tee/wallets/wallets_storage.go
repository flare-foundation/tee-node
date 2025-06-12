package wallets

import (
	"sync"

	"github.com/pkg/errors"
)

var walletsStorage = InitWalletsStorage()

type WalletsStorage struct {
	Storage map[WalletKeyIdPair]*Wallet

	sync.RWMutex
}

func InitWalletsStorage() WalletsStorage {
	return WalletsStorage{Storage: make(map[WalletKeyIdPair]*Wallet)}
}

func StoreWallet(wallet *Wallet) error {
	idPair := WalletKeyIdPair{WalletId: wallet.WalletId, KeyId: wallet.KeyId}
	walletsStorage.Lock()
	defer walletsStorage.Unlock()
	if _, ok := walletsStorage.Storage[idPair]; ok {
		return errors.New("wallet with given walletId and keyId already exists")
	}

	walletsStorage.Storage[idPair] = wallet

	return nil
}

func RemoveWallet(idPair WalletKeyIdPair) {
	walletsStorage.Lock()
	defer walletsStorage.Unlock()

	delete(walletsStorage.Storage, idPair)
}

func GetWallet(idPair WalletKeyIdPair) (*Wallet, error) {
	walletsStorage.Lock()
	defer walletsStorage.Unlock()

	wallet, ok := walletsStorage.Storage[idPair]
	if !ok || wallet == nil {
		return nil, errors.New("wallet non-existent")
	}

	return wallet, nil
}

func WalletExists(idPair WalletKeyIdPair) bool {
	walletsStorage.Lock()
	defer walletsStorage.Unlock()

	_, ok := walletsStorage.Storage[idPair]
	return ok
}

func DestroyState() {
	walletsStorage.Lock()
	defer walletsStorage.Unlock()

	walletsStorage.Storage = make(map[WalletKeyIdPair]*Wallet)
}
