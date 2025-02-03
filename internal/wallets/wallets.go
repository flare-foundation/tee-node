package wallets

import (
	"crypto/ecdsa"
	"tee-node/internal/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

var wallets map[string]Wallet = make(map[string]Wallet)

var walletRequests map[string]WalletRequests = make(map[string]WalletRequests)

type Wallet struct {
	PrivateKey *ecdsa.PrivateKey
	Address    common.Address
}

type WalletRequests struct {
	Request    map[common.Address]bool
	Weight     int
	PolicyHash string
}

func CreateNewWallet(name string) (string, error) {
	sk, err := utils.GenerateEthereumPrivateKey()
	if err != nil {
		return "", err
	}

	newWallet := Wallet{PrivateKey: sk, Address: crypto.PubkeyToAddress(sk.PublicKey)}
	wallets[name] = newWallet

	return newWallet.Address.Hex(), nil
}

// TODO: check signature
func ProcessNewWalletRequest(name string, signature []byte) (bool, string, error) {
	return true, common.Address{}.Hex(), nil
}

// todo: add attestation
func GetPublicKey(name string) (string, error) {
	wallet, ok := wallets[name]
	if !ok {
		return "", errors.New("wallet non-existent")
	}

	return wallet.Address.Hex(), nil
}
