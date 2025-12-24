package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/flare-foundation/tee-node/pkg/types"
)

func makeHash(data string) []byte {
	return crypto.Keccak256([]byte(data))
}

func makeWalletPubKey(t *testing.T, key *ecdsa.PrivateKey) wallet.PublicKey {
	t.Helper()

	pubStruct := types.PubKeyToStruct(&key.PublicKey)
	return wallet.PublicKey{X: pubStruct.X, Y: pubStruct.Y}
}

func TestSign(t *testing.T) {
	privKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	hash := makeHash("message")
	sig, err := Sign(hash, privKey)
	require.NoError(t, err)

	// Confirm signature recovers the signer.
	addr, err := SignatureToSignersAddress(hash, sig)
	require.NoError(t, err)
	assert.Equal(t, crypto.PubkeyToAddress(privKey.PublicKey), addr)

	t.Run("invalid hash length", func(t *testing.T) {
		_, err := Sign([]byte{0x01}, privKey)
		assert.EqualError(t, err, "invalid message hash length")
	})
}

func TestCheckAndVerifySignature(t *testing.T) {
	privKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	otherKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	hash := makeHash("payload")
	sig, err := Sign(hash, privKey)
	require.NoError(t, err)

	voters := []common.Address{crypto.PubkeyToAddress(privKey.PublicKey)}

	t.Run("check signature with voters allowed", func(t *testing.T) {
		addr, err := CheckSignature(hash, sig, voters)
		require.NoError(t, err)
		assert.Equal(t, voters[0], addr)
	})

	t.Run("check signature rejects non voter", func(t *testing.T) {
		_, err := CheckSignature(hash, sig, []common.Address{crypto.PubkeyToAddress(otherKey.PublicKey)})
		assert.EqualError(t, err, "not a voter")
	})

	t.Run("verify signature success", func(t *testing.T) {
		err := VerifySignature(hash, sig, voters[0])
		assert.NoError(t, err)
	})

	t.Run("verify signature wrong signer", func(t *testing.T) {
		err := VerifySignature(hash, sig, crypto.PubkeyToAddress(otherKey.PublicKey))
		assert.EqualError(t, err, "signature check fail")
	})
}

func TestSignatureToSignersAddress(t *testing.T) {
	privKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	hash := makeHash("sig-address")
	sig, err := Sign(hash, privKey)
	require.NoError(t, err)

	addr, err := SignatureToSignersAddress(hash, sig)
	require.NoError(t, err)
	assert.Equal(t, crypto.PubkeyToAddress(privKey.PublicKey), addr)
}

func TestParsePubKeys(t *testing.T) {
	pk, err := crypto.GenerateKey()
	require.NoError(t, err)

	pub := makeWalletPubKey(t, pk)
	parsed, err := ParsePubKeys([]wallet.PublicKey{pub})
	require.NoError(t, err)
	require.Len(t, parsed, 1)
	assert.Equal(t, pk.X, parsed[0].X)
	assert.Equal(t, pk.Y, parsed[0].Y)

	t.Run("invalid key", func(t *testing.T) {
		invalid := wallet.PublicKey{}
		keys, err := ParsePubKeys([]wallet.PublicKey{invalid})
		assert.Nil(t, keys)
		assert.EqualError(t, err, "invalid public key bytes")
	})
}

func TestPubKeysToAddresses(t *testing.T) {
	privKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	pubStruct := types.PubKeyToStruct(&privKey.PublicKey)

	addresses, err := PubKeysToAddresses([]types.PublicKey{pubStruct})
	require.NoError(t, err)
	require.Len(t, addresses, 1)
	assert.Equal(t, crypto.PubkeyToAddress(privKey.PublicKey), addresses[0])

	t.Run("invalid public key bytes", func(t *testing.T) {
		invalid := types.PublicKey{}
		addrs, err := PubKeysToAddresses([]types.PublicKey{invalid})
		assert.Nil(t, addrs)
		assert.EqualError(t, err, "invalid public key bytes")
	})
}

func TestECIESConversions(t *testing.T) {
	privKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	t.Run("pub key conversion success", func(t *testing.T) {
		eciesPub, err := ECDSAPubKeyToECIES(&privKey.PublicKey)
		require.NoError(t, err)
		assert.NotNil(t, eciesPub)
		assert.Equal(t, privKey.X, eciesPub.X)
		assert.Equal(t, privKey.Y, eciesPub.Y)
	})

	t.Run("priv key conversion success", func(t *testing.T) {
		eciesPriv, err := ECDSAPrivKeyToECIES(privKey)
		require.NoError(t, err)
		assert.Equal(t, privKey.D, eciesPriv.D)
	})

	t.Run("unsupported curve", func(t *testing.T) {
		p256key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		eciesPub, err := ECDSAPubKeyToECIES(&p256key.PublicKey)
		assert.Nil(t, eciesPub)
		assert.EqualError(t, err, "curve not S256")
	})
}
