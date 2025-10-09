package utils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/pkg/types"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// GenerateRandom returns a cryptographically secure 32-byte random value.
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

// Sign signs the provided hash with the given private key.
func Sign(msgHash []byte, privKey *ecdsa.PrivateKey) ([]byte, error) {
	if len(msgHash) != 32 {
		return nil, fmt.Errorf("invalid message hash length")
	}

	sig, err := crypto.Sign(accounts.TextHash(msgHash), privKey)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// CheckSignature recovers the signer address and optionally verifies it is in
// the allowed voter list.
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

// VerifySignature ensures the signature matches the expected signer.
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

// SignatureToSignersAddress recovers the Ethereum address associated with the
// signature of the given hash.
func SignatureToSignersAddress(hash, signature []byte) (common.Address, error) {
	pubKey, err := crypto.SigToPub(accounts.TextHash(hash), signature)
	if err != nil {
		return common.Address{}, err
	}
	address := crypto.PubkeyToAddress(*pubKey)

	return address, nil
}

// ParsePubKeys converts the wallet public key structures to ECDSA keys.
func ParsePubKeys(pubKeys []wallet.PublicKey) ([]*ecdsa.PublicKey, error) {
	parsedPubKeys := make([]*ecdsa.PublicKey, len(pubKeys))
	var err error
	for i, key := range pubKeys {
		parsedPubKeys[i], err = types.ParsePubKey(types.PublicKey{
			X: key.X,
			Y: key.Y,
		})
		if err != nil {
			return nil, err
		}
	}

	return parsedPubKeys, nil
}

// PubKeysToAddresses returns the Ethereum addresses derived from the keys.
func PubKeysToAddresses(pubKeys []types.PublicKey) ([]common.Address, error) {
	addresses := make([]common.Address, len(pubKeys))
	for i, pubKey := range pubKeys {
		parsedPubKey, err := types.ParsePubKey(pubKey)
		if err != nil {
			return nil, err
		}
		addresses[i] = crypto.PubkeyToAddress(*parsedPubKey)
	}

	return addresses, nil
}

func ECDSAPubKeyToECIES(pubKey *ecdsa.PublicKey) (*ecies.PublicKey, error) {
	if pubKey.Curve != secp256k1.S256() && pubKey.Curve != crypto.S256() {
		return nil, errors.New("curve not S256")
	}

	return &ecies.PublicKey{X: pubKey.X, Y: pubKey.Y, Curve: ecies.DefaultCurve, Params: ecies.ECIES_AES128_SHA256}, nil
}

func ECDSAPrivKeyToECIES(privKey *ecdsa.PrivateKey) (*ecies.PrivateKey, error) {
	pubKey, err := ECDSAPubKeyToECIES(&privKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return &ecies.PrivateKey{PublicKey: *pubKey, D: privKey.D}, nil
}
