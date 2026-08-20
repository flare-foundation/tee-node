package vrf_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/tee-node/pkg/wallets/vrf"
	"github.com/stretchr/testify/require"
)

// TestHashToCurveMatchesContractVector pins the hash-to-curve output for a fixed
// key and message. The expected point is cross-validated against
// VrfVerifier._hashToCurve, so a change to the preimage encoding that would
// silently desynchronise proof generation from on-chain verification fails here
// without needing a simulated chain.
func TestHashToCurveMatchesContractVector(t *testing.T) {
	key, err := crypto.ToECDSA(hexutil.MustDecode(
		"0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"))
	require.NoError(t, err)

	h := vrf.HashToCurve(&key.PublicKey, hexutil.MustDecode("0xdeadbeefcafe"))
	require.NotNil(t, h)

	require.Equal(t,
		"4beed689e0207e1aa873f54ec0eb1c8f8886bac5f71867c3363367e207c8d858",
		h.X.Text(16))
	require.Equal(t,
		"49a96c28502c2c71cb85ca3147e24be706c5824e037b08aa3ebd19e86f3d1709",
		h.Y.Text(16))
}

func TestVrfHappyPath(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	for range 50 {
		nonce := randomNonce(t)

		proof, err := vrf.VerifiableRandomness(key, nonce)
		require.NoError(t, err)

		err = vrf.VerifyRandomness(proof, &key.PublicKey, nonce)
		require.NoError(t, err)

		randomness, err := proof.RandomnessFromProof()
		require.NoError(t, err)
		require.NotEqual(t, common.Hash{}, randomness)
	}
}

func TestScalarBaseMultErrorsWhenScalarTooLarge(t *testing.T) {
	_, err := vrf.ScalarBaseMult(bigInt257Bits())
	require.Error(t, err)
	require.Contains(t, err.Error(), "scalar is not in range [0, N)")
}

func TestScalarBaseMultErrorsWhenScalarNil(t *testing.T) {
	_, err := vrf.ScalarBaseMult(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "scalar is nil")
}

func TestScalarMultErrorsWhenPointNotOnCurve(t *testing.T) {
	_, err := vrf.ScalarMult(&vrf.Point{X: big.NewInt(1), Y: big.NewInt(1)}, big.NewInt(1))
	require.Error(t, err)
	require.Contains(t, err.Error(), "point not on curve")
}

func TestScalarMultErrorsWhenPointNil(t *testing.T) {
	_, err := vrf.ScalarMult(nil, big.NewInt(1))
	require.Error(t, err)
	require.Contains(t, err.Error(), "point is nil")
}

func TestScalarMultErrorsWhenPointCoordsNil(t *testing.T) {
	_, err := vrf.ScalarMult(&vrf.Point{X: nil, Y: big.NewInt(1)}, big.NewInt(1))
	require.Error(t, err)
	require.Contains(t, err.Error(), "point coordinates are nil")
}

func TestScalarMultErrorsWhenScalarNil(t *testing.T) {
	p, err := vrf.ScalarBaseMult(big.NewInt(2))
	require.NoError(t, err)

	_, err = vrf.ScalarMult(p, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "scalar is nil")
}

func TestScalarMultErrorsWhenScalarTooLarge(t *testing.T) {
	p, err := vrf.ScalarBaseMult(big.NewInt(2))
	require.NoError(t, err)

	_, err = vrf.ScalarMult(p, bigInt257Bits())
	require.Error(t, err)
	require.Contains(t, err.Error(), "scalar is not in range [0, N)")
}

func TestAddErrorsWhenFirstPointNotOnCurve(t *testing.T) {
	p2, err := vrf.ScalarBaseMult(big.NewInt(2))
	require.NoError(t, err)

	_, err = vrf.Add(&vrf.Point{X: big.NewInt(1), Y: big.NewInt(1)}, p2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "point not on curve")
}

func TestAddErrorsWhenFirstPointNil(t *testing.T) {
	p2, err := vrf.ScalarBaseMult(big.NewInt(2))
	require.NoError(t, err)

	_, err = vrf.Add(nil, p2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "point is nil")
}

func TestAddErrorsWhenSecondPointNil(t *testing.T) {
	p1, err := vrf.ScalarBaseMult(big.NewInt(2))
	require.NoError(t, err)

	_, err = vrf.Add(p1, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "point is nil")
}

func TestAddErrorsWhenSecondPointNotOnCurve(t *testing.T) {
	p1, err := vrf.ScalarBaseMult(big.NewInt(2))
	require.NoError(t, err)

	_, err = vrf.Add(p1, &vrf.Point{X: big.NewInt(1), Y: big.NewInt(1)})
	require.Error(t, err)
	require.Contains(t, err.Error(), "point not on curve")
}

func TestAddErrorsWhenFirstPointCoordsNil(t *testing.T) {
	p2, err := vrf.ScalarBaseMult(big.NewInt(2))
	require.NoError(t, err)

	_, err = vrf.Add(&vrf.Point{X: nil, Y: big.NewInt(1)}, p2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "point coordinates are nil")
}

func TestAddErrorsWhenSecondPointCoordsNil(t *testing.T) {
	p1, err := vrf.ScalarBaseMult(big.NewInt(2))
	require.NoError(t, err)

	_, err = vrf.Add(p1, &vrf.Point{X: big.NewInt(1), Y: nil})
	require.Error(t, err)
	require.Contains(t, err.Error(), "point coordinates are nil")
}

func TestVerifiableRandomnessErrorsWithTooLargeSecretKey(t *testing.T) {
	pk, err := vrf.ScalarBaseMult(big.NewInt(1))
	require.NoError(t, err)

	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{X: pk.X, Y: pk.Y}, D: bigInt257Bits()}

	_, err = vrf.VerifiableRandomness(key, randomNonce(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "scalar is not in range [0, N)")
}

func TestVerifiableRandomnessErrorsWhenKeyNil(t *testing.T) {
	_, err := vrf.VerifiableRandomness(nil, randomNonce(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "key is nil")
}

func TestVerifiableRandomnessErrorsWhenPublicKeyNil(t *testing.T) {
	key := &ecdsa.PrivateKey{D: big.NewInt(1)}
	_, err := vrf.VerifiableRandomness(key, randomNonce(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "point coordinates are nil")
}

func TestVerifiableRandomnessErrorsWhenSecretKeyNil(t *testing.T) {
	pk, err := vrf.ScalarBaseMult(big.NewInt(1))
	require.NoError(t, err)

	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{X: pk.X, Y: pk.Y}}
	_, err = vrf.VerifiableRandomness(key, randomNonce(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "scalar is nil")
}

func TestVerifiableRandomnessErrorsWhenPublicKeyNotOnCurve(t *testing.T) {
	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{X: big.NewInt(1), Y: big.NewInt(1)}, D: big.NewInt(1)}
	_, err := vrf.VerifiableRandomness(key, randomNonce(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "point not on curve")
}

func TestVerifyRandomnessErrorsWhenPkNotOnCurve(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	nonce := randomNonce(t)
	proof, err := vrf.VerifiableRandomness(key, nonce)
	require.NoError(t, err)

	err = vrf.VerifyRandomness(proof, &ecdsa.PublicKey{X: big.NewInt(1), Y: big.NewInt(1)}, nonce)
	require.Error(t, err)
	require.Contains(t, err.Error(), "point not on curve")
}

func TestVerifyRandomnessErrorsWhenPkNil(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	nonce := randomNonce(t)
	proof, err := vrf.VerifiableRandomness(key, nonce)
	require.NoError(t, err)

	err = vrf.VerifyRandomness(proof, nil, nonce)
	require.Error(t, err)
	require.Contains(t, err.Error(), "point is nil")
}

func TestVerifyRandomnessErrorsWhenSIsTooLarge(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	nonce := randomNonce(t)
	proof, err := vrf.VerifiableRandomness(key, nonce)
	require.NoError(t, err)

	proof.S = bigInt257Bits()
	err = vrf.VerifyRandomness(proof, &key.PublicKey, nonce)
	require.Error(t, err)
	require.Contains(t, err.Error(), "scalar is not in range [0, N)")
}

func TestVerifyRandomnessErrorsWhenCIsNil(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	nonce := randomNonce(t)
	proof, err := vrf.VerifiableRandomness(key, nonce)
	require.NoError(t, err)

	proof.C = nil
	err = vrf.VerifyRandomness(proof, &key.PublicKey, nonce)
	require.Error(t, err)
	require.Contains(t, err.Error(), "scalar is nil")
}

func TestVerifyRandomnessErrorsWhenSIsNil(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	nonce := randomNonce(t)
	proof, err := vrf.VerifiableRandomness(key, nonce)
	require.NoError(t, err)

	proof.S = nil
	err = vrf.VerifyRandomness(proof, &key.PublicKey, nonce)
	require.Error(t, err)
	require.Contains(t, err.Error(), "scalar is nil")
}

func TestVerifyRandomnessErrorsWhenGammaIsNil(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	nonce := randomNonce(t)
	proof, err := vrf.VerifiableRandomness(key, nonce)
	require.NoError(t, err)

	proof.Gamma = nil
	err = vrf.VerifyRandomness(proof, &key.PublicKey, nonce)
	require.Error(t, err)
	require.Contains(t, err.Error(), "point is nil")
}

func TestVerifyRandomnessErrorsWhenGammaNotOnCurve(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	nonce := randomNonce(t)
	proof, err := vrf.VerifiableRandomness(key, nonce)
	require.NoError(t, err)

	proof.Gamma = &vrf.Point{X: big.NewInt(1), Y: big.NewInt(1)}
	err = vrf.VerifyRandomness(proof, &key.PublicKey, nonce)
	require.Error(t, err)
	require.Contains(t, err.Error(), "point not on curve")
}

func TestVerifyRandomnessFailsWithWrongNonce(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	nonce := randomNonce(t)
	proof, err := vrf.VerifiableRandomness(key, nonce)
	require.NoError(t, err)

	err = vrf.VerifyRandomness(proof, &key.PublicKey, randomNonce(t))
	require.Error(t, err)
}

func TestVerifyRandomnessFailsWithTamperedProof(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	nonce := randomNonce(t)
	proof, err := vrf.VerifiableRandomness(key, nonce)
	require.NoError(t, err)

	proof.C = new(big.Int).Add(proof.C, big.NewInt(1))
	err = vrf.VerifyRandomness(proof, &key.PublicKey, nonce)
	require.Error(t, err)
}

func TestVerifyRandomnessErrorsWhenProofNil(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	err = vrf.VerifyRandomness(nil, &key.PublicKey, randomNonce(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "proof is nil")
}

func TestHashToG1DeterministicAndOnCurve(t *testing.T) {
	nonce := randomNonce(t)

	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	p1 := vrf.HashToCurve(&key.PublicKey, nonce)
	p2 := vrf.HashToCurve(&key.PublicKey, nonce)

	require.Equal(t, 0, p1.X.Cmp(p2.X))
	require.Equal(t, 0, p1.Y.Cmp(p2.Y))
	require.True(t, p1.IsOnCurve())
}

// TestHashToCurveIsPublicKeySalted checks that the hash-to-curve point is bound
// to the public key, so precomputation against one key does not carry to another.
func TestHashToCurveIsPublicKeySalted(t *testing.T) {
	nonce := randomNonce(t)

	keyA, err := crypto.GenerateKey()
	require.NoError(t, err)
	keyB, err := crypto.GenerateKey()
	require.NoError(t, err)

	pA := vrf.HashToCurve(&keyA.PublicKey, nonce)
	pB := vrf.HashToCurve(&keyB.PublicKey, nonce)

	require.NotEqual(t, 0, pA.X.Cmp(pB.X), "same message under different keys must not map to the same point")
	require.True(t, pA.IsOnCurve())
	require.True(t, pB.IsOnCurve())
}

// TestVerifiableRandomnessIsDeterministic checks that proof generation does not
// depend on the RNG: the same key and message must yield a byte-identical proof.
func TestVerifiableRandomnessIsDeterministic(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	nonce := randomNonce(t)

	first, err := vrf.VerifiableRandomness(key, nonce)
	require.NoError(t, err)
	second, err := vrf.VerifiableRandomness(key, nonce)
	require.NoError(t, err)

	require.Equal(t, 0, first.C.Cmp(second.C))
	require.Equal(t, 0, first.S.Cmp(second.S))
	require.Equal(t, 0, first.Gamma.X.Cmp(second.Gamma.X))
	require.Equal(t, 0, first.Gamma.Y.Cmp(second.Gamma.Y))
	require.Equal(t, 0, first.U.X.Cmp(second.U.X))
	require.Equal(t, 0, first.V.X.Cmp(second.V.X))
	require.Equal(t, 0, first.ZInv.Cmp(second.ZInv))
}

// TestVerifiableRandomnessNonceVariesPerKeyAndMessage checks that the deterministic
// nonce is not reused across keys or messages, since a repeated nonce under
// distinct challenges would expose the secret scalar.
func TestVerifiableRandomnessNonceVariesPerKeyAndMessage(t *testing.T) {
	keyA, err := crypto.GenerateKey()
	require.NoError(t, err)
	keyB, err := crypto.GenerateKey()
	require.NoError(t, err)

	nonce1 := randomNonce(t)
	nonce2 := randomNonce(t)

	// u = k·G, so distinct u values imply distinct nonces.
	a1, err := vrf.VerifiableRandomness(keyA, nonce1)
	require.NoError(t, err)
	a2, err := vrf.VerifiableRandomness(keyA, nonce2)
	require.NoError(t, err)
	b1, err := vrf.VerifiableRandomness(keyB, nonce1)
	require.NoError(t, err)

	require.NotEqual(t, 0, a1.U.X.Cmp(a2.U.X), "same key, different message must not reuse the nonce")
	require.NotEqual(t, 0, a1.U.X.Cmp(b1.U.X), "different key, same message must not reuse the nonce")
}

func TestAddMatchesScalarBaseMult(t *testing.T) {
	p2, err := vrf.ScalarBaseMult(big.NewInt(2))
	require.NoError(t, err)

	p3, err := vrf.ScalarBaseMult(big.NewInt(3))
	require.NoError(t, err)

	sum, err := vrf.Add(p2, p3)
	require.NoError(t, err)

	p5, err := vrf.ScalarBaseMult(big.NewInt(5))
	require.NoError(t, err)

	require.Equal(t, 0, sum.X.Cmp(p5.X))
	require.Equal(t, 0, sum.Y.Cmp(p5.Y))
}

func bigInt257Bits() *big.Int {
	n := big.NewInt(1)
	return n.Lsh(n, 256)
}

func randomNonce(t *testing.T) []byte {
	t.Helper()
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	require.NoError(t, err)
	return nonce
}
