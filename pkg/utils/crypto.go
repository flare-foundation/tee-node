package utils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"io"
	"slices"

	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/tee"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/pkg/types"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

func GenerateRandom() ([32]byte, error) {
	b := make([]byte, 32)
	n, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return [32]byte{}, err
	}
	if n != 32 {
		return [32]byte{}, errors.New("failed to read random 32 bytes")
	}

	var r [32]byte
	copy(r[:], b)

	return r, nil
}

// GenerateEthereumPrivateKey generates a new Ethereum private key
func GenerateEthereumPrivateKey() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}

func Sign(msgHash []byte, privKey *ecdsa.PrivateKey) ([]byte, error) {
	if len(msgHash) != 32 {
		return nil, errors.Errorf("invalid message hash length")
	}

	hashSignature, err := crypto.Sign(accounts.TextHash(msgHash), privKey)
	if err != nil {
		return nil, err
	}
	return hashSignature, nil
}

// PubkeyToAddress converts an Ethereum public key to an Ethereum address
func PubkeyToAddress(pubkey *ecdsa.PublicKey) common.Address {
	return crypto.PubkeyToAddress(*pubkey)
}

func CheckSignature(hash, signature []byte, voters []common.Address) (common.Address, error) {
	address, err := SignatureToSignersAddress(hash, signature)
	if err != nil {
		return common.Address{}, err
	}
	if voters != nil && !slices.Contains(voters, address) {
		return common.Address{}, errors.New("not a voter")
	}

	return address, nil
}

func VerifySignature(hash, signature []byte, signerAddress common.Address) error {
	address, err := SignatureToSignersAddress(hash, signature)
	if err != nil {
		return err
	}
	if address != signerAddress {
		return errors.New("signature check fail")
	}

	return nil
}

func SignatureToSignersAddress(hash, signature []byte) (common.Address, error) {
	pubKey, err := crypto.SigToPub(accounts.TextHash(hash), signature)
	if err != nil {
		return common.Address{}, err
	}
	address := crypto.PubkeyToAddress(*pubKey)

	return address, nil
}

func ParsePubKeys(pubKeys []wallet.PublicKey) ([]*ecdsa.PublicKey, error) {
	parsedPubKeys := make([]*ecdsa.PublicKey, len(pubKeys))
	var err error
	for i, key := range pubKeys {
		parsedPubKeys[i], err = types.ParsePubKey(tee.PublicKey(key))
		if err != nil {
			return nil, err
		}
	}

	return parsedPubKeys, nil
}
