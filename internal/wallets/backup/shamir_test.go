package backup_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/flare-foundation/tee-node/internal/wallets/backup"
	"github.com/flare-foundation/tee-node/pkg/wallets"
	pkgbackup "github.com/flare-foundation/tee-node/pkg/wallets/backup"
)

func shamirTestField(t *testing.T) *pkgbackup.Field {
	t.Helper()

	field, err := pkgbackup.FieldFor(wallets.EVMType, wallets.EVMSignAlgo)
	require.NoError(t, err)

	return field
}

func TestSplitAndCombineShamirShares(t *testing.T) {
	field := shamirTestField(t)

	val := make([]byte, field.Size)
	_, err := rand.Read(val)
	require.NoError(t, err)
	val[0] = 0 // keep the value below the group order

	numShares := uint64(5)
	threshold := uint64(3)

	shares, err := backup.SplitToShamirShares(field, val, numShares, threshold)
	assert.NoError(t, err)
	assert.Len(t, shares, int(numShares))

	reconstructedSecret, err := backup.CombineShamirShares(field, shares[:threshold])
	assert.NoError(t, err)
	assert.Equal(t, val, reconstructedSecret)
}

// TestShareEncodingIsFixedWidth checks that a share's serialized size does not
// depend on its value, so an encrypted split's length reveals nothing about the
// shares it carries.
func TestShareEncodingIsFixedWidth(t *testing.T) {
	field := shamirTestField(t)

	for range 200 {
		val := make([]byte, field.Size)
		_, err := rand.Read(val)
		require.NoError(t, err)
		val[0] = 0

		shares, err := backup.SplitToShamirShares(field, val, 3, 2)
		require.NoError(t, err)

		for _, share := range shares {
			require.Len(t, share.Y, field.Size)
		}
	}
}

// TestCombineShamirSharesAnyThresholdSubset checks that any threshold-sized
// subset of shares reconstructs the same secret.
func TestCombineShamirSharesAnyThresholdSubset(t *testing.T) {
	field := shamirTestField(t)

	val := make([]byte, field.Size)
	_, err := rand.Read(val)
	require.NoError(t, err)
	val[0] = 0

	shares, err := backup.SplitToShamirShares(field, val, 5, 3)
	require.NoError(t, err)

	subsets := [][]int{{0, 1, 2}, {1, 3, 4}, {0, 2, 4}, {2, 3, 4}}
	for _, idx := range subsets {
		subset := []pkgbackup.ShamirShare{shares[idx[0]], shares[idx[1]], shares[idx[2]]}

		got, err := backup.CombineShamirShares(field, subset)
		require.NoError(t, err)
		require.True(t, bytes.Equal(val, got), "subset %v reconstructed a different secret", idx)
	}
}

func TestSplitToShamirShares_ThresholdGreaterThanNumShares(t *testing.T) {
	field := shamirTestField(t)

	shares, err := backup.SplitToShamirShares(field, []byte{0x01}, 3, 4)
	assert.Error(t, err)
	assert.Nil(t, shares)
}

func TestCombineShamirShares_DoubleShareError(t *testing.T) {
	field := shamirTestField(t)

	numShares := uint64(3)
	threshold := uint64(2)

	shares, err := backup.SplitToShamirShares(field, []byte{0x49, 0x96, 0x02, 0xd2}, numShares, threshold)
	assert.NoError(t, err)
	assert.Len(t, shares, int(numShares))

	// Introduce a double share error by modifying the shares manually
	shares[1].X = shares[0].X

	_, err = backup.CombineShamirShares(field, shares[:threshold])
	assert.Error(t, err)
}
