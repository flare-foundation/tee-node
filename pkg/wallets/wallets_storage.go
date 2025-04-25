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
	delete(walletsStorage.Storage, idPair)
	walletsStorage.Unlock()

}

func GetWallet(idPair WalletKeyIdPair) (*Wallet, error) {
	walletsStorage.Lock()
	wallet, ok := walletsStorage.Storage[idPair]
	walletsStorage.Unlock()
	if !ok {
		return nil, errors.New("wallet non-existent")
	}

	return wallet, nil
}

func WalletExists(idPair WalletKeyIdPair) bool {
	walletsStorage.Lock()
	_, ok := walletsStorage.Storage[idPair]
	walletsStorage.Unlock()

	return ok
}

// Note: This is useful for tests, but it would also be useful for upgrades, where a TEE get's shutdown.
func DestroyState() {
	walletsStorage.Lock()
	defer walletsStorage.Unlock()

	walletsStorage.Storage = make(map[WalletKeyIdPair]*Wallet)
	backupWalletsStorage.Storage = make(map[WalletBackupId]*WalletBackup)
	pendingBackupWalletsStorage.Storage = make(map[WalletBackupId]*PendingWalletBackup)
}
