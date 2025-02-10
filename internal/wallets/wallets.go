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
}

func CreateNewWallet(name string) (string, error) {
	sk, err := utils.GenerateEthereumPrivateKey()
	if err != nil {
		return "", err
	}

	newWallet := Wallet{Name: name, PrivateKey: sk, Address: crypto.PubkeyToAddress(sk.PublicKey)}
	wallets[name] = &newWallet

	return newWallet.Address.Hex(), nil
}

// todo: add attestation
func GetPublicKey(name string) (string, error) {
	wallet, ok := wallets[name]
	if !ok {
		return "", errors.New("wallet non-existent")
	}

	return wallet.Address.Hex(), nil
}

func AddWallet(wallet *Wallet) error {

	wallets[wallet.Name] = wallet

	return nil
}
