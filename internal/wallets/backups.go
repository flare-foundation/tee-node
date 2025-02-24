package wallets

import "sync"

var BackupWallets = InitBackupWalletsStorage()

type BackupWalletsStorage struct {
	Storage map[string]map[string]WalletShare

	sync.Mutex
}

func InitBackupWalletsStorage() BackupWalletsStorage {
	return BackupWalletsStorage{Storage: make(map[string]map[string]WalletShare)}
}
