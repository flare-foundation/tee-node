package utils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"io"
	"slices"
	api "tee-node/api/types"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/box"

	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}

	return b, nil
}

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
	pubKey, err := crypto.SigToPub(accounts.TextHash(hash), signature)
	if err != nil {
		return common.Address{}, err
	}
	address := crypto.PubkeyToAddress(*pubKey)
	if voters != nil && !slices.Contains(voters, address) {
		return common.Address{}, errors.New("not a voter")
	}

	return address, nil
}

func VerifySignature(hash, signature []byte, signerAddress common.Address) error {
	pubKey, err := crypto.SigToPub(accounts.TextHash(hash), signature)
	if err != nil {
		return err
	}
	address := crypto.PubkeyToAddress(*pubKey)
	if address != signerAddress {
		return errors.New("signature check fail")
	}

	return nil
}

// NOTE: XRP and EVM signing might be combinable into one function, but it fails for now
// NOTE: I leave them seperately for now and I will research later if they can be merged.
func XrpSign(txHash []byte, privKey *ecdsa.PrivateKey) []byte {
	priv, _ := btcec.PrivKeyFromBytes(privKey.D.Bytes())
	sig2 := btcecdsa.Sign(priv, txHash)

	return sig2.Serialize()
}

func XrpVerifySig(txHash []byte, txSignature []byte, pubKey *ecdsa.PublicKey) (bool, error) {
	pubKeyBytes := SerializeCompressed(pubKey) // NOTE: Do we need to compress the public key or not?

	sig, err := btcecdsa.ParseDERSignature(txSignature)
	if err != nil {
		return false, err
	}
	pk, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return false, nil
	}
	return sig.Verify(txHash, pk), nil
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

type EncryptionKey struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

// GenerateEncryptionKeyPair generates a new private key for
// encryption.
func GenerateEncryptionKeyPair() (EncryptionKey, error) {
	pubKey, privKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return EncryptionKey{}, err
	}

	key := EncryptionKey{PrivateKey: *privKey, PublicKey: *pubKey}

	return key, nil
}

func VerifyThresholdSignatures(message []byte, signers []common.Address, signatures [][]byte, threshold uint8) (bool, error) {
	signersMap := make(map[common.Address]bool)
	weight := 0
	for _, signature := range signatures {

		signer, err := CheckSignature(message, signature, signers)
		if err != nil {
			return false, err
		}
		if signersMap[signer] {
			return false, errors.New("duplicate signer")
		}

		signersMap[signer] = true
		weight += 1
	}

	return weight >= int(threshold), nil
}

func VerifyPauserSignature(message api.Hashable, pausingAddresses []common.Address, signatures [][]byte) error {
	messageHash, err := message.Hash()
	if err != nil {
		return err
	}
	if len(signatures) != 1 {
		return errors.Errorf("expected exactly one signature, got %d", len(signatures))
	}

	_, err = CheckSignature(messageHash[:], signatures[0], pausingAddresses)
	if err != nil {
		if err.Error() == "not a voter" {
			return errors.New("pauser address not in the list of pauserAddresses")
		}
		return err
	}

	return nil
}
