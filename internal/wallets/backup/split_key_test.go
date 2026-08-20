package backup

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/flare-foundation/tee-node/pkg/wallets"
	pkgbackup "github.com/flare-foundation/tee-node/pkg/wallets/backup"
)

func generateTestPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	privateKey, err := crypto.GenerateKey()
	assert.NoError(t, err)
	return privateKey
}

func testField(t *testing.T) *pkgbackup.Field {
	t.Helper()

	field, err := pkgbackup.FieldFor(wallets.EVMType, wallets.EVMSignAlgo)
	require.NoError(t, err)

	return field
}

func TestSplitSecret(t *testing.T) {
	field := testField(t)
	secret := common.BigToHash(generateTestPrivateKey(t).D).Bytes()

	splits, err := SplitSecret(field, secret, 3)
	assert.NoError(t, err)
	assert.Len(t, splits, 3)
	for _, split := range splits {
		assert.Len(t, split, field.Size)
	}

	splits, err = SplitSecret(field, secret, 1)
	assert.Error(t, err)
	assert.Nil(t, splits)
}

func TestJoinSecret(t *testing.T) {
	field := testField(t)
	secret := common.BigToHash(generateTestPrivateKey(t).D).Bytes()

	splits, err := SplitSecret(field, secret, 3)
	require.NoError(t, err)

	joined, err := JoinSecret(field, splits...)
	assert.NoError(t, err)
	assert.Equal(t, secret, joined)

	joined, err = JoinSecret(field)
	assert.Error(t, err)
	assert.Nil(t, joined)
}

// TestSplitSecretRejectsOversizedSecret checks that a value the field cannot
// represent is refused rather than silently reduced, which would reconstruct a
// different secret.
func TestSplitSecretRejectsOversizedSecret(t *testing.T) {
	field := testField(t)

	tooLarge := bytes.Repeat([]byte{0xff}, 32) // exceeds the secp256k1 group order
	_, err := SplitSecret(field, tooLarge, 2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not fit the sharing field")
}

// TestSplitSecretOverLargerFieldAcceptsAny32Bytes checks that the field defined
// for arbitrary 32-byte secrets round-trips values above the curve order.
func TestSplitSecretOverLargerFieldAcceptsAny32Bytes(t *testing.T) {
	field, err := pkgbackup.FieldForID(pkgbackup.FieldPrimeAbove256ID)
	require.NoError(t, err)

	for _, secret := range [][]byte{
		bytes.Repeat([]byte{0xff}, 32),
		bytes.Repeat([]byte{0x00}, 32),
		randomBytes(t, 32),
	} {
		splits, err := SplitSecret(field, secret, 2)
		require.NoError(t, err)

		joined, err := JoinSecret(field, splits...)
		require.NoError(t, err)

		// The larger field encodes elements in 33 bytes; the secret is the
		// low-order 32.
		require.Equal(t, field.Size, len(joined))
		require.True(t, bytes.Equal(secret, joined[field.Size-32:]))
		require.Zero(t, joined[0])
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()

	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)

	return b
}
