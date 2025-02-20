package wallets

import (
	"crypto/ecdsa"
	"tee-node/internal/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

var wallets map[string]*Wallet = make(map[string]*Wallet)

type Wallet struct {
	Name       string
	PrivateKey *ecdsa.PrivateKey
	Address    common.Address
	XrpAddress string
}

func CreateNewWallet(name string) (string, error) {
	sk, err := utils.GenerateEthereumPrivateKey()
	if err != nil {
		return "", err
	}

	sec1PubKey := utils.SerializeCompressed(&sk.PublicKey)
	xrpAddress, err := utils.GetXrpAddressFromPubkey(sec1PubKey)
	if err != nil {
		return "", err
	}

	newWallet := Wallet{Name: name, PrivateKey: sk, Address: crypto.PubkeyToAddress(sk.PublicKey), XrpAddress: xrpAddress}
	wallets[name] = &newWallet

	return newWallet.Address.Hex(), nil
}

func GetXrpAddress(name string) (string, error) {
	wallet, ok := wallets[name]
	if !ok {
		return "", errors.New("wallet non-existent")
	}

	return wallet.XrpAddress, nil
}

func GetEthAddress(name string) (string, error) {
	wallet, ok := wallets[name]
	if !ok {
		return "", errors.New("wallet non-existent")
	}

	return wallet.Address.Hex(), nil
}

func GetPublicKey(name string) (*ecdsa.PublicKey, error) {
	wallet, ok := wallets[name]
	if !ok {
		return nil, errors.New("wallet non-existent")
	}

	return &wallet.PrivateKey.PublicKey, nil
}

func AddWallet(wallet *Wallet) error {
	wallets[wallet.Name] = wallet

	return nil
}

func RemoveWallet(walletName string) {
	delete(wallets, walletName)
}

func GetWallet(name string) (*Wallet, error) {
	wallet, ok := wallets[name]
	if !ok {
		return nil, errors.New("wallet non-existent")
	}

	return wallet, nil
}

func WalletExists(name string) bool {
	_, ok := wallets[name]
	return ok
}

// Note: This is useful for tests, but it would also be useful for upgrades, where a TEE get's shutdown.
func DestroyState() {
	wallets = make(map[string]*Wallet)
}
