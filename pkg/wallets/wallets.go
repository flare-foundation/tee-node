package wallets

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"sync"
	"tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

var walletsStorage = InitWalletsStorage()

// Wallet is a struct carrying the private key of particular wallet. It
// should never be modified, after being created. Todo: check this
type Wallet struct {
	WalletId   common.Hash
	KeyId      *big.Int
	PrivateKey *ecdsa.PrivateKey
	Address    common.Address
	XrpAddress string
}
type WalletsStorage struct {
	// walletId to ShareId to WalletShare
	Storage map[string]*Wallet

	sync.Mutex
}

type WalletKeyIdPair struct {
	WalletId common.Hash
	KeyId    *big.Int
}

func (w *WalletKeyIdPair) Id() string {
	return fmt.Sprintf("%v:%v", w.WalletId.Hex(), w.KeyId.String())
}

func InitWalletsStorage() WalletsStorage {
	return WalletsStorage{Storage: make(map[string]*Wallet)}
}

func CreateNewWallet(idPair WalletKeyIdPair) error {
	sk, err := utils.GenerateEthereumPrivateKey()
	if err != nil {
		return err
	}

	sec1PubKey := utils.SerializeCompressed(&sk.PublicKey)
	xrpAddress, err := utils.GetXrpAddressFromPubkey(sec1PubKey)
	if err != nil {
		return err
	}

	newWallet := Wallet{WalletId: idPair.WalletId, KeyId: idPair.KeyId, PrivateKey: sk, Address: crypto.PubkeyToAddress(sk.PublicKey), XrpAddress: xrpAddress}
	walletsStorage.Lock()
	walletsStorage.Storage[idPair.Id()] = &newWallet
	walletsStorage.Unlock()

	return nil
}

func GetXrpAddress(idPair WalletKeyIdPair) (string, error) {
	walletsStorage.Lock()
	wallet, ok := walletsStorage.Storage[idPair.Id()]
	walletsStorage.Unlock()

	if !ok {
		return "", errors.New("wallet non-existent")
	}

	return wallet.XrpAddress, nil
}

func GetEthAddress(idPair WalletKeyIdPair) (string, error) {
	walletsStorage.Lock()
	wallet, ok := walletsStorage.Storage[idPair.Id()]
	walletsStorage.Unlock()
	if !ok {
		return "", errors.New("wallet non-existent")
	}

	return wallet.Address.Hex(), nil
}

func GetPublicKey(idPair WalletKeyIdPair) (*ecdsa.PublicKey, error) {
	walletsStorage.Lock()
	wallet, ok := walletsStorage.Storage[idPair.Id()]
	walletsStorage.Unlock()
	if !ok {
		return nil, errors.New("wallet non-existent")
	}

	return &wallet.PrivateKey.PublicKey, nil
}

func AddWallet(wallet *Wallet) error {
	walletsStorage.Lock()
	idPair := WalletKeyIdPair{WalletId: wallet.WalletId, KeyId: wallet.KeyId}
	walletsStorage.Storage[idPair.Id()] = wallet
	walletsStorage.Unlock()

	return nil
}

func RemoveWallet(idPair WalletKeyIdPair) {
	walletsStorage.Lock()
	delete(walletsStorage.Storage, idPair.Id())
	walletsStorage.Unlock()

}

func GetWallet(idPair WalletKeyIdPair) (*Wallet, error) {
	walletsStorage.Lock()
	wallet, ok := walletsStorage.Storage[idPair.Id()]
	walletsStorage.Unlock()
	if !ok {
		return nil, errors.New("wallet non-existent")
	}

	return wallet, nil
}

func WalletExists(idPair WalletKeyIdPair) bool {
	walletsStorage.Lock()
	_, ok := walletsStorage.Storage[idPair.Id()]
	walletsStorage.Unlock()

	return ok
}

// Note: This is useful for tests, but it would also be useful for upgrades, where a TEE get's shutdown.
func DestroyState() {
	walletsStorage.Lock()
	defer walletsStorage.Unlock()

	walletsStorage.Storage = make(map[string]*Wallet)
}
