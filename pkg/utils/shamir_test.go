package utils

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitAndCombineShamirShares(t *testing.T) {
	// Test case 1: Simple secret with 5 shares and threshold of 3
	val, err := rand.Int(rand.Reader, P)
	assert.NoError(t, err)

	numShares := uint64(5)
	threshold := uint64(3)

	shares, err := SplitToShamirShares(val, numShares, threshold)
	assert.NoError(t, err)
	assert.Len(t, shares, int(numShares))

	// Test case 2: Reconstruct secret from shares
	reconstructedSecret, err := CombineShamirShares(shares[:threshold])
	assert.NoError(t, err)
	assert.Equal(t, val, reconstructedSecret)
}

func TestSplitToShamirShares_ThresholdGreaterThanNumShares(t *testing.T) {
	val := big.NewInt(1234567890)
	numShares := uint64(3)
	threshold := uint64(4) // Threshold is greater than number of shares

	shares, err := SplitToShamirShares(val, numShares, threshold)
	assert.Error(t, err)
	assert.Nil(t, shares)
}

func TestCombineShamirShares_DoubleShareError(t *testing.T) {
	// Custom test case to simulate double share error
	val := big.NewInt(1234567890)
	numShares := uint64(3)
	threshold := uint64(2)

	shares, err := SplitToShamirShares(val, numShares, threshold)
	assert.NoError(t, err)
	assert.Len(t, shares, int(numShares))

	// Introduce a double share error by modifying the shares manually
	shares[1].X = shares[0].X

	_, err = CombineShamirShares(shares[:threshold])
	assert.Error(t, err)
}
