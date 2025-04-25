package utils

import (
	"crypto/ecdsa"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

func generateTestPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	privateKey, err := crypto.GenerateKey()
	assert.NoError(t, err)
	return privateKey
}

func TestSplitPrivateKey(t *testing.T) {
	privateKey := generateTestPrivateKey(t)

	// Test with valid number of splits
	splits, err := SplitPrivateKey(privateKey, 3)
	assert.NoError(t, err)
	assert.Len(t, splits, 3)

	// Test with invalid number of splits
	splits, err = SplitPrivateKey(privateKey, 1)
	assert.Error(t, err)
	assert.Nil(t, splits)
}

func TestJoinPrivateKeys(t *testing.T) {
	privateKey := generateTestPrivateKey(t)

	// Split the private key
	splits, err := SplitPrivateKey(privateKey, 3)
	assert.NoError(t, err)

	// Join the private keys
	joinedKey, err := JoinPrivateKeys(splits)
	assert.NoError(t, err)
	assert.Equal(t, privateKey.D, joinedKey.D)

	// Test with no private keys
	joinedKey, err = JoinPrivateKeys([]*ecdsa.PrivateKey{})
	assert.Error(t, err)
	assert.Nil(t, joinedKey)
}
