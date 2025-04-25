package wallets

import (
	"sync"
	api "tee-node/api/types"

	"github.com/pkg/errors"
)

var pendingBackupWalletsStorage = InitPendingBackupWalletsStorage()

type PendingWalletBackupStorage struct {
	Storage map[WalletBackupId]*PendingWalletBackup

	sync.RWMutex
}

type PendingWalletBackup struct {
	WalletBackup        *WalletBackup
	ProvidersKeySplits  []*KeySplit
	AdminsKeySplits     []*KeySplit
	AdminsPubKeysMap    map[api.ECDSAPublicKey]uint64
	ProvidersPubKeysMap map[api.ECDSAPublicKey]uint64

	sync.RWMutex
}

func (pendingWalletBackup *PendingWalletBackup) ProvidersWeight() uint64 {
	weightSum := uint64(0)
	for _, weight := range pendingWalletBackup.ProvidersPubKeysMap {
		weightSum += weight
	}
	return weightSum
}

func (pendingWalletBackup *PendingWalletBackup) AdminsWeight() uint64 {
	weightSum := uint64(0)
	for _, weight := range pendingWalletBackup.AdminsPubKeysMap {
		weightSum += weight
	}
	return weightSum
}

func InitPendingBackupWalletsStorage() PendingWalletBackupStorage {
	return PendingWalletBackupStorage{Storage: make(map[WalletBackupId]*PendingWalletBackup)}
}

func InitPendingBackup(walletBackupId WalletBackupId) error {
	pendingBackupWalletsStorage.Lock()
	defer pendingBackupWalletsStorage.Unlock()
	_, ok := pendingBackupWalletsStorage.Storage[walletBackupId]
	if ok {
		return errors.New("pending wallet backup already exists")
	}

	pendingBackupWalletsStorage.Storage[walletBackupId] = &PendingWalletBackup{
		ProvidersKeySplits:  make([]*KeySplit, 0),
		AdminsKeySplits:     make([]*KeySplit, 0),
		AdminsPubKeysMap:    make(map[api.ECDSAPublicKey]uint64),
		ProvidersPubKeysMap: make(map[api.ECDSAPublicKey]uint64),
	}

	return nil
}

func StorePendingBackup(walletBackup *WalletBackup) error {
	pendingBackupWalletsStorage.Lock()
	pendingBackupWallet, ok := pendingBackupWalletsStorage.Storage[walletBackup.WalletBackupId]
	pendingBackupWalletsStorage.Unlock()
	if !ok {
		return errors.New("no ongoing wallet restoration process with the given backup ID")
	}

	pendingBackupWallet.Lock()
	defer pendingBackupWallet.Unlock()
	if pendingBackupWallet.WalletBackup != nil {
		return errors.New("wallet backup package already uploaded")
	}
	pendingBackupWallet.WalletBackup = walletBackup

	return nil
}

func CheckPendingBackupSplitStorage(keySplit *KeySplit, isAdmin bool) error {
	pendingBackupWalletsStorage.RLock()
	pendingWalletBackup := pendingBackupWalletsStorage.Storage[keySplit.WalletBackupId]
	pendingBackupWalletsStorage.RUnlock()

	pendingWalletBackup.RLock()
	defer pendingWalletBackup.RUnlock()
	if isAdmin {
		if _, ok := pendingWalletBackup.AdminsPubKeysMap[keySplit.OwnerPublicKey]; ok {
			return errors.New("the key split of the provider given public key already exists")
		}

		if keySplit.PartialPubKey != pendingWalletBackup.WalletBackup.AdminEncryptedParts.PublicKey {
			return errors.New("the provided admin share data does not match required public key")
		}

	} else {
		if _, ok := pendingWalletBackup.ProvidersPubKeysMap[keySplit.OwnerPublicKey]; ok {
			return errors.New("the key split of the provider given public key already exists")
		}

		if keySplit.PartialPubKey != pendingWalletBackup.WalletBackup.ProvidersEncryptedParts.PublicKey {
			return errors.New("the provided provider share data does not match required public key")
		}
	}

	return nil
}

func StorePendingBackupAdminSplit(keySplit *KeySplit) {
	pendingBackupWalletsStorage.RLock()
	pendingWalletBackup := pendingBackupWalletsStorage.Storage[keySplit.WalletBackupId]
	pendingBackupWalletsStorage.RUnlock()

	pendingWalletBackup.Lock()
	pendingWalletBackup.AdminsKeySplits = append(pendingWalletBackup.AdminsKeySplits, keySplit)
	pendingWalletBackup.AdminsPubKeysMap[keySplit.OwnerPublicKey] = uint64(len(keySplit.Shares))
	pendingWalletBackup.Unlock()
}

func StorePendingBackupProviderSplit(keySplit *KeySplit) {
	pendingBackupWalletsStorage.RLock()
	pendingWalletBackup := pendingBackupWalletsStorage.Storage[keySplit.WalletBackupId]
	pendingBackupWalletsStorage.RUnlock()

	pendingWalletBackup.Lock()
	pendingWalletBackup.ProvidersKeySplits = append(pendingWalletBackup.ProvidersKeySplits, keySplit)
	pendingWalletBackup.ProvidersPubKeysMap[keySplit.OwnerPublicKey] = uint64(len(keySplit.Shares))
	pendingWalletBackup.Unlock()
}

func RemovePendingBackup(walletBackupId WalletBackupId) {
	pendingBackupWalletsStorage.Lock()
	delete(pendingBackupWalletsStorage.Storage, walletBackupId)
	pendingBackupWalletsStorage.Unlock()
}

func GetPendingBackup(walletBackupId WalletBackupId) (*WalletBackup, error) {
	pendingBackupWalletsStorage.RLock()
	pendingBackup, ok := pendingBackupWalletsStorage.Storage[walletBackupId]
	pendingBackupWalletsStorage.RUnlock()
	if !ok {
		return nil, errors.New("no ongoing wallet restoration process with the given backup ID")
	}

	pendingBackup.RLock()
	defer pendingBackup.RUnlock()
	if pendingBackup.WalletBackup == nil {
		return nil, errors.New("backup package not uploaded yet")
	}

	return pendingBackup.WalletBackup, nil
}

func IsPendingBackupThresholdReached(walletBackupId WalletBackupId) (bool, error) {
	pendingBackupWalletsStorage.RLock()
	pendingBackup, ok := pendingBackupWalletsStorage.Storage[walletBackupId]
	pendingBackupWalletsStorage.RUnlock()
	if !ok {
		return false, errors.New("no ongoing wallet restoration process with the given backup ID")
	}

	pendingBackup.RLock()
	checkAdmin := pendingBackup.WalletBackup.AdminEncryptedParts.Threshold <= pendingBackup.AdminsWeight()
	checkProvider := pendingBackup.WalletBackup.ProvidersEncryptedParts.Threshold <= pendingBackup.ProvidersWeight()
	pendingBackup.RUnlock()

	return checkAdmin && checkProvider, nil
}

func PendingWalletBackupRecover(walletBackupId WalletBackupId) (*Wallet, error) {
	pendingBackupWalletsStorage.Lock()
	defer pendingBackupWalletsStorage.Unlock()

	pendingBackup, ok := pendingBackupWalletsStorage.Storage[walletBackupId]
	if !ok {
		return nil, errors.New("no ongoing wallet restoration process with the given backup ID")
	}
	pendingBackup.RLock()
	defer pendingBackup.RUnlock()
	wallet, err := RecoverWallet(
		pendingBackup.AdminsKeySplits,
		pendingBackup.WalletBackup.AdminEncryptedParts.PublicKey,
		pendingBackup.WalletBackup.AdminEncryptedParts.Threshold,
		pendingBackup.ProvidersKeySplits,
		pendingBackup.WalletBackup.ProvidersEncryptedParts.PublicKey,
		pendingBackup.WalletBackup.ProvidersEncryptedParts.Threshold,
		pendingBackup.WalletBackup.WalletBackupMetaData,
	)
	if err != nil {
		return nil, err
	}

	return wallet, nil
}
