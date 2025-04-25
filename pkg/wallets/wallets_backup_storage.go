package wallets

import (
	"crypto/ecdsa"
	"sync"

	"github.com/pkg/errors"
)

var backupWalletsStorage = InitBackupWalletsStorage()

type WalletBackupStorage struct {
	Storage map[WalletBackupId]*WalletBackup

	sync.RWMutex
}

func InitBackupWalletsStorage() WalletBackupStorage {
	return WalletBackupStorage{Storage: make(map[WalletBackupId]*WalletBackup)}
}

func StoreBackup(walletBackup *WalletBackup) {
	backupWalletsStorage.Lock()
	backupWalletsStorage.Storage[walletBackup.WalletBackupId] = walletBackup
	backupWalletsStorage.Unlock()
}

func RemoveBackup(walletBackupId WalletBackupId) {
	backupWalletsStorage.Lock()
	delete(backupWalletsStorage.Storage, walletBackupId)
	backupWalletsStorage.Unlock()
}

func GetBackup(walletBackupId WalletBackupId) (*WalletBackup, error) {
	backupWalletsStorage.RLock()
	backup, ok := backupWalletsStorage.Storage[walletBackupId]
	backupWalletsStorage.RUnlock()
	if !ok {
		return nil, errors.New("backup does not exists")
	}

	return backup, nil
}

func UpdateBackupStorage(newStorage map[WalletBackupId]*WalletBackup) {
	backupWalletsStorage.Lock()
	defer backupWalletsStorage.Unlock()
	backupWalletsStorage.Storage = newStorage
}

func NewBackupWalletsStorageWithNewPolicy(providersPubKeys []*ecdsa.PublicKey, providersThreshold uint64, weights []uint16, rewardEpochId uint32) (map[WalletBackupId]*WalletBackup, error) {
	backupWalletsStorage.Lock()
	defer backupWalletsStorage.Unlock()
	walletsStorage.RLock()
	defer walletsStorage.RUnlock()

	newBackupWalletsStorage := make(map[WalletBackupId]*WalletBackup)

	for walletBackupId := range backupWalletsStorage.Storage {
		walletKey := WalletKeyIdPair{WalletId: walletBackupId.WalletId, KeyId: walletBackupId.KeyId}
		newWalletBackup, err := BackupWallet(walletsStorage.Storage[walletKey], providersPubKeys, providersThreshold, weights, rewardEpochId)
		if err != nil {
			return nil, err
		}
		newBackupWalletsStorage[walletBackupId] = newWalletBackup
	}

	return newBackupWalletsStorage, nil
}
