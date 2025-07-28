package wallets

import (
	"sync"

	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/pkg/errors"
)

var Storage = InitWalletsStorage()

type WalletsStorage struct {
	// if a wallet exists, its Status attribute should
	// point to the same struct as is saved in permanent
	wallets   map[types.WalletKeyIdPair]*Wallet
	permanent map[types.WalletKeyIdPair]*WalletStatus

	sync.RWMutex
}

func InitWalletsStorage() *WalletsStorage {
	return &WalletsStorage{
		wallets:   make(map[types.WalletKeyIdPair]*Wallet),
		permanent: make(map[types.WalletKeyIdPair]*WalletStatus),
	}
}

func (walletsStorage *WalletsStorage) StoreWallet(wallet *Wallet) error {
	idPair := types.WalletKeyIdPair{WalletId: wallet.WalletId, KeyId: wallet.KeyId}
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

func (walletsStorage *WalletsStorage) RemoveWallet(idPair types.WalletKeyIdPair) {
	delete(walletsStorage.wallets, idPair)
}

func (walletsStorage *WalletsStorage) GetWallet(idPair types.WalletKeyIdPair) (*Wallet, error) {
	wallet, ok := walletsStorage.wallets[idPair]
	if !ok || wallet == nil {
		return nil, errors.New("wallet non-existent")
	}
	walletCopy := CopyWallet(wallet)

	return walletCopy, nil
}

func (walletsStorage *WalletsStorage) GetWallets() []*Wallet {
	wallets := make([]*Wallet, len(walletsStorage.wallets))
	i := 0
	for _, wallet := range walletsStorage.wallets {
		wallets[i] = CopyWallet(wallet)
		i++
	}

	return wallets
}

func (walletsStorage *WalletsStorage) WalletExists(idPair types.WalletKeyIdPair) bool {
	_, ok := walletsStorage.wallets[idPair]
	return ok
}

func (walletsStorage *WalletsStorage) CheckNonce(idPair types.WalletKeyIdPair, nonce uint64) error {
	walletStatus, ok := walletsStorage.permanent[idPair]
	if !ok {
		return nil
	}
	if nonce <= walletStatus.Nonce {
		return errors.New("nonce too small")
	}

	return nil
}

func (walletsStorage *WalletsStorage) GetNonce(idPair types.WalletKeyIdPair) (uint64, error) {
	walletStatus, ok := walletsStorage.permanent[idPair]
	if !ok {
		return 0, errors.New("no wallet nonce")
	}

	return walletStatus.Nonce, nil
}

func (walletsStorage *WalletsStorage) UpdateNonce(idPair types.WalletKeyIdPair, nonce uint64) {
	if walletStatus, ok := walletsStorage.permanent[idPair]; ok {
		walletStatus.Nonce = nonce
	}
}

func (walletsStorage *WalletsStorage) DestroyState() {
	walletsStorage.Lock()
	defer walletsStorage.Unlock()

	walletsStorage.wallets = make(map[types.WalletKeyIdPair]*Wallet)
	walletsStorage.permanent = make(map[types.WalletKeyIdPair]*WalletStatus)
}
