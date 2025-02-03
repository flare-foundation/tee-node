package utils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"io"
	insecure_rand "math/rand"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
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

// VerifySignature verifies a signature against a message hash
func VerifySignature(pubKey *ecdsa.PublicKey, msgHash []byte, signature []byte) bool {
	return crypto.VerifySignature(crypto.CompressPubkey(pubKey), accounts.TextHash(msgHash), signature[:len(signature)-1])
}

func RandomNormalizedArray(n int, seed int64) []float64 {
	// Initialize random source with seed
	r := insecure_rand.New(insecure_rand.NewSource(seed))

	// Generate random numbers
	numbers := make([]float64, n)
	sum := 0.0

	for i := 0; i < n; i++ {
		// Generate random float between 0 and 1
		numbers[i] = r.Float64()
		sum += numbers[i]
	}

	// Normalize to sum to 1
	for i := 0; i < n; i++ {
		numbers[i] /= sum
	}

	return numbers
}
