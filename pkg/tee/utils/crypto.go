package utils

import (
	"crypto/ecdsa"
	"fmt"
	"slices"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"

	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// GenerateEthereumPrivateKey generates a new Ethereum private key
func GenerateEthereumPrivateKey() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}

// PubkeyToAddress converts an Ethereum public key to an Ethereum address
func PubkeyToAddress(pubkey *ecdsa.PublicKey) common.Address {
	return crypto.PubkeyToAddress(*pubkey)
}

func Sign(msgHash []byte, privKey *ecdsa.PrivateKey) ([]byte, error) {
	if len(msgHash) != 32 {
		return nil, fmt.Errorf("invalid message hash length")
	}

	hashSignature, err := crypto.Sign(accounts.TextHash(msgHash), privKey)
	if err != nil {
		return nil, err
	}
	return hashSignature, nil
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
// NOTE: I leave them seperately for now and I will research later if they can be merged.
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

// type Hashable interface {
// 	Hash() (common.Hash, error)
// }

// func VerifyPauserSignature(message Hashable, pausingAddresses []common.Address, signatures [][]byte) error {
// 	messageHash, err := message.Hash()
// 	if err != nil {
// 		return err
// 	}
// 	if len(signatures) != 1 {
// 		return errors.Errorf("expected exactly one signature, got %d", len(signatures))
// 	}

// 	_, err = CheckSignature(messageHash[:], signatures[0], pausingAddresses)
// 	if err != nil {
// 		if err.Error() == "not a voter" {
// 			return errors.New("pauser address not in the list of pauserAddresses")
// 		}
// 		return err
// 	}

// 	return nil
// }
