package utils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"io"
	"slices"

	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/tee"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/pkg/types"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
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

// NOTE: XRP and EVM signing might be combinable into one function, but it fails for now
// NOTE: I leave them separately for now and I will research later if they can be merged.
func XrpSign(txHash []byte, privKey *ecdsa.PrivateKey) []byte {
	priv, _ := btcec.PrivKeyFromBytes(privKey.D.Bytes())
	sig2 := btcecdsa.Sign(priv, txHash)

	return sig2.Serialize()
}

// SerializeCompressed serializes the public key to the compressed format.
// Reference1: https://crypto.stackexchange.com/questions/96104/what-is-was-sec1-ecc-public-key-leading-octet-0x01-for
// Reference2: https://www.secg.org/sec1-v2.pdf Chapter 2.3.3
// Reference3: https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
func SerializeCompressed(pubKey *ecdsa.PublicKey) []byte {
	// 0x02 or 0x03 || 32-byte x coordinate
	var prefix []byte
	if pubKey.Y.Bit(0) == 0 {
		prefix = []byte{0x02}
	} else {
		prefix = []byte{0x03}
	}

	pubKeyBytes := pubKey.X.Bytes()
	if len(pubKeyBytes) < 32 {
		pubKeyBytes = append(make([]byte, 32-len(pubKeyBytes)), pubKeyBytes...)
	}
	// 0x02 or 0x03 || 32-byte x coordinate
	final := append(prefix, pubKeyBytes...)
	return final
}

const XRP_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

// This should be a sec1 encoded public key
// You can use SerializeCompressed to get the sec1 encoded public key
func GetXrpAddressFromPubkey(publicKey []byte) (string, error) {
	if len(publicKey) != 33 {
		return "", fmt.Errorf("invalid public key length")
	}

	account := Sha256RipeMD160(publicKey)

	var accBytes = make([]byte, 0, 20+1)
	accBytes = append(accBytes, byte(0))
	accBytes = append(accBytes, account[:]...)

	address := Base58Encode(accBytes, XRP_ALPHABET)

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
