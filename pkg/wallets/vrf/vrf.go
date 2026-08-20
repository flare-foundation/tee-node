package vrf

import (
	"crypto/ecdsa"
	"errors"
	"math/big"

	dcrsecp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

var (
	one          = big.NewInt(1)
	uint256Ty, _ = abi.NewType("uint256", "uint256", nil)
	s256Curve    = secp256k1.S256()
	// basePoint is the curve generator. It is read-only and safe to share
	// across calls; scalar multiplication never mutates its operand point.
	basePoint = &Point{X: secp256k1.S256().Gx, Y: secp256k1.S256().Gy}
	arguments = abi.Arguments{{Type: uint256Ty}, {Type: uint256Ty}, {Type: uint256Ty},
		{Type: uint256Ty}, {Type: uint256Ty}, {Type: uint256Ty},
		{Type: uint256Ty}, {Type: uint256Ty}, {Type: uint256Ty},
		{Type: uint256Ty}, {Type: uint256Ty}, {Type: uint256Ty}}
)

// nonceIterationLimit bounds how many RFC 6979 nonces are tried before proof
// generation is abandoned. Each iteration fails only on a zero ZInv denominator,
// which occurs with probability ≈ 1/P.
const nonceIterationLimit = 8

type Point struct {
	X *big.Int
	Y *big.Int
}

// IsOnCurve reports whether the point lies on the secp256k1 curve.
func (p *Point) IsOnCurve() bool {
	return s256Curve.IsOnCurve(p.X, p.Y)
}

// validateScalar checks that k is a non-nil integer in [1, N-1]. It is intended
// for public scalars; secret ones go through toScalar, whose range check does
// not branch on the operand's magnitude.
func validateScalar(k *big.Int) error {
	if k == nil {
		return errors.New("scalar is nil")
	}
	if k.Cmp(s256Curve.N) >= 0 || k.Sign() <= 0 {
		return errors.New("scalar is not in range [0, N)")
	}

	return nil
}

// ValidatePoint checks that the point is non-nil and lies on the secp256k1 curve.
func (p *Point) ValidatePoint() error {
	if p == nil {
		return errors.New("point is nil")
	}
	if p.X == nil || p.Y == nil {
		return errors.New("point coordinates are nil")
	}
	if !p.IsOnCurve() {
		return errors.New("point not on curve")
	}
	return nil
}

// ScalarBaseMult returns k*G, where G is the base point of the group and k is
// an integer.
func ScalarBaseMult(k *big.Int) (*Point, error) {
	s, err := toScalar(k)
	if err != nil {
		return nil, err
	}
	defer s.Zero()

	return scalarBaseMult(s)
}

// ScalarMult returns k*P, where P is provided point of the group and k is
// an integer.
func ScalarMult(p *Point, k *big.Int) (*Point, error) {
	s, err := toScalar(k)
	if err != nil {
		return nil, err
	}
	defer s.Zero()

	return scalarMult(p, s)
}

// scalarBaseMult returns k*G for a scalar already in modular form.
func scalarBaseMult(k *dcrsecp256k1.ModNScalar) (*Point, error) {
	return scalarMult(basePoint, k)
}

// scalarMult returns k*P for a scalar already in modular form. The scalar is
// consumed in its fixed-width encoding and the underlying curve multiplication
// is constant time, so neither the scalar's value nor its magnitude influences
// timing. Secret scalars should reach the curve through this entry point rather
// than through the big.Int variants.
func scalarMult(p *Point, k *dcrsecp256k1.ModNScalar) (*Point, error) {
	if err := p.ValidatePoint(); err != nil {
		return nil, err
	}
	if k.IsZero() {
		return nil, errors.New("scalar is not in range [0, N)")
	}

	kBytes := k.Bytes()
	defer clear(kBytes[:])

	x, y := s256Curve.ScalarMult(p.X, p.Y, kBytes[:])
	if x == nil || y == nil {
		return nil, errors.New("scalar multiplication failed")
	}

	return &Point{X: x, Y: y}, nil
}

// toScalar converts an integer into modular form, rejecting nil and values
// outside [1, N-1]. The range check runs on the fixed-width encoding rather
// than through big.Int comparison, whose early-exit loop leaks the operand's
// magnitude. The caller owns the returned scalar and should zero it when done.
func toScalar(k *big.Int) (*dcrsecp256k1.ModNScalar, error) {
	if k == nil {
		return nil, errors.New("scalar is nil")
	}
	if k.Sign() < 0 || k.BitLen() > 256 {
		return nil, errors.New("scalar is not in range [0, N)")
	}

	var buf [32]byte
	k.FillBytes(buf[:])
	defer clear(buf[:])

	s := new(dcrsecp256k1.ModNScalar)
	if s.SetBytes(&buf) != 0 || s.IsZero() {
		s.Zero()

		return nil, errors.New("scalar is not in range [0, N)")
	}

	return s, nil
}

// Add returns P1 + P2, where P1 and P2 are provided points of the group.
func Add(p1 *Point, p2 *Point) (*Point, error) {
	if err := p1.ValidatePoint(); err != nil {
		return nil, err
	}
	if err := p2.ValidatePoint(); err != nil {
		return nil, err
	}

	x, y := s256Curve.Add(p1.X, p1.Y, p2.X, p2.Y)

	return &Point{X: x, Y: y}, nil
}

// Proof represents a generated verifiable randomness together with a proof of
// its correctness. It mirrors the Proof struct in VRFVerifier.sol.
//
// The four witness points (U, CGamma, V, ZInv) are pre-computed by VerifiableRandomness
// and are required by the on-chain VRFVerifier contract to avoid expensive
// secp256k1 scalar multiplications or BigModExp inside the EVM.
type Proof struct {
	Gamma *Point   // gamma = sk · HashToCurve(pk, nonce)
	C     *big.Int // challenge scalar
	S     *big.Int // response scalar  s = k − sk·c mod N

	// Witness points (computed off-chain, verified on-chain via ecrecover)
	U      *Point   // u = c·pk + s·G
	CGamma *Point   // c·gamma  (intermediate for verifying V)
	V      *Point   // v = c·gamma + s·h
	ZInv   *big.Int // modInv(CGamma.X − V.X, P); field element in [1, P)
}

func (p *Proof) validateProofFormat() error {
	if p == nil {
		return errors.New("proof is nil")
	}
	if err := p.Gamma.ValidatePoint(); err != nil {
		return err
	}
	if err := validateScalar(p.C); err != nil {
		return err
	}
	if err := validateScalar(p.S); err != nil {
		return err
	}
	if err := p.U.ValidatePoint(); err != nil {
		return err
	}
	if err := p.CGamma.ValidatePoint(); err != nil {
		return err
	}
	if err := p.V.ValidatePoint(); err != nil {
		return err
	}
	if p.ZInv == nil {
		return errors.New("ZInv is nil")
	}
	if p.ZInv.Sign() == 0 || p.ZInv.Cmp(s256Curve.P) >= 0 {
		return errors.New("ZInv is not in range [1, P)")
	}
	return nil
}

func validatePublicKey(pk *ecdsa.PublicKey) error {
	if pk == nil {
		return errors.New("point is nil")
	}
	if pk.X == nil || pk.Y == nil {
		return errors.New("point coordinates are nil")
	}
	if !s256Curve.IsOnCurve(pk.X, pk.Y) {
		return errors.New("point not on curve")
	}
	return nil
}

// validateKey checks the key's public half. The secret scalar is validated
// separately by toScalar, whose range check runs in constant time.
func validateKey(key *ecdsa.PrivateKey) error {
	if key == nil {
		return errors.New("key is nil")
	}

	return validatePublicKey(&key.PublicKey)
}

// VerifiableRandomness creates a deterministic verifiable randomness (with proof) given a
// private key and a nonce.
func VerifiableRandomness(key *ecdsa.PrivateKey, nonce []byte) (*Proof, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}

	h := HashToCurve(&key.PublicKey, nonce)
	if h == nil {
		return nil, errors.New("failed to hash to curve")
	}

	// The secret key is converted once and used in modular form throughout, so
	// it never re-enters variable-time big.Int arithmetic.
	secret, err := toScalar(key.D)
	if err != nil {
		return nil, err
	}
	defer secret.Zero()

	gamma, err := scalarMult(h, secret)
	if err != nil {
		return nil, err
	}

	for iteration := range uint32(nonceIterationLimit) {
		k := nonceRFC6979(secret, h, iteration)

		u, err := scalarBaseMult(k) // u = k·G  (equals c·pk + s·G after c,s are fixed)
		if err != nil {
			return nil, err
		}
		v, err := scalarMult(h, k) // v = k·h  (equals c·gamma + s·h after c,s are fixed)
		if err != nil {
			return nil, err
		}

		toHash, err := arguments.Pack(
			s256Curve.Gx, s256Curve.Gy,
			h.X, h.Y,
			key.X, key.Y,
			gamma.X, gamma.Y,
			u.X, u.Y,
			v.X, v.Y,
		)
		if err != nil {
			return nil, err
		}

		c := HashToZn(toHash)

		s := scalarSubProduct(k, secret, c)
		k.Zero() // last use of the nonce; the response scalar is public

		cGamma, err := ScalarMult(gamma, c)
		if err != nil {
			return nil, err
		}

		// ZInv = modInv(cGamma.X − v.X, P). A zero denominator (probability ≈ 1/P)
		// yields a proof the contract rejects, so the nonce generator is advanced
		// rather than reused. cGamma, v and zInv are all published in the proof,
		// so constant-time arithmetic on them is not needed.
		denom := new(big.Int).Sub(cGamma.X, v.X)
		denom.Mod(denom, s256Curve.P)
		if denom.Sign() == 0 {
			continue
		}
		zInv := new(big.Int).ModInverse(denom, s256Curve.P)

		return &Proof{Gamma: gamma, C: c, S: s, U: u, CGamma: cGamma, V: v, ZInv: zInv}, nil
	}

	return nil, errors.New("proof generation failed: nonce iteration limit reached")
}

// VerifyRandomness verifies that the provided randomness corresponds to the
// provider's public key and nonce. Used for off-chain checks; actual
// verification is done by the VRFVerifier contract on-chain.
//
// Full verification requires four independent checks:
//  1. U == c·pk + s·G          (prover knows sk such that pk = sk·G)
//  2. CGamma == c·gamma         (CGamma is correctly derived from gamma and c)
//  3. V == CGamma + s·h         (V is correctly derived from gamma, h, c, s)
//  4. c == HashToZn(Pack(G, h, pk, gamma, U, V))
func VerifyRandomness(proof *Proof, pk *ecdsa.PublicKey, nonce []byte) error {
	if err := validatePublicKey(pk); err != nil {
		return err
	}
	if err := proof.validateProofFormat(); err != nil {
		return err
	}

	h := HashToCurve(pk, nonce)
	if h == nil {
		return errors.New("failed to hash to curve")
	}
	// check ZInv
	denom := new(big.Int).Sub(proof.CGamma.X, proof.V.X)
	denom.Mod(denom, s256Curve.P)
	checkZ := new(big.Int).Mul(proof.ZInv, denom)
	checkZ.Mod(checkZ, s256Curve.P)
	if checkZ.Cmp(one) != 0 {
		return errors.New("proof verification failed: invalid ZInv")
	}

	pkPoint := &Point{X: pk.X, Y: pk.Y}

	// check U
	pkToC, err := ScalarMult(pkPoint, proof.C)
	if err != nil {
		return err
	}
	gToS, err := ScalarBaseMult(proof.S)
	if err != nil {
		return err
	}
	expectedU, err := Add(pkToC, gToS)
	if err != nil {
		return err
	}
	if expectedU.X.Cmp(proof.U.X) != 0 || expectedU.Y.Cmp(proof.U.Y) != 0 {
		return errors.New("proof verification failed: invalid U witness")
	}

	// check CGamma
	expectedCGamma, err := ScalarMult(proof.Gamma, proof.C)
	if err != nil {
		return err
	}
	if expectedCGamma.X.Cmp(proof.CGamma.X) != 0 || expectedCGamma.Y.Cmp(proof.CGamma.Y) != 0 {
		return errors.New("proof verification failed: invalid CGamma witness")
	}

	// check V
	hToS, err := ScalarMult(h, proof.S)
	if err != nil {
		return err
	}
	expectedV, err := Add(expectedCGamma, hToS)
	if err != nil {
		return err
	}
	if expectedV.X.Cmp(proof.V.X) != 0 || expectedV.Y.Cmp(proof.V.Y) != 0 {
		return errors.New("proof verification failed: invalid V witness")
	}

	// verify challenge proof
	toHash, err := arguments.Pack(
		s256Curve.Gx, s256Curve.Gy,
		h.X, h.Y,
		pkPoint.X, pkPoint.Y,
		proof.Gamma.X, proof.Gamma.Y,
		proof.U.X, proof.U.Y,
		proof.V.X, proof.V.Y,
	)
	if err != nil {
		return err
	}
	if HashToZn(toHash).Cmp(proof.C) != 0 {
		return errors.New("proof verification failed: challenge hash mismatch")
	}

	return nil
}

// RandomnessFromProof extracts the verifiable randomness output from a valid proof
// by hashing the gamma point coordinates.
func (proof *Proof) RandomnessFromProof() (common.Hash, error) {
	if err := proof.Gamma.ValidatePoint(); err != nil {
		return common.Hash{}, err
	}
	sum := crypto.Keccak256(encodePointCoordinates(proof.Gamma.X, proof.Gamma.Y))

	return common.BytesToHash(sum), nil
}

// encodePointCoordinates serializes a pair of field elements as two 32-byte
// big-endian values, matching abi.encodePacked(uint256,uint256) on-chain.
func encodePointCoordinates(x, y *big.Int) []byte {
	buf := make([]byte, 64)
	x.FillBytes(buf[:32])
	y.FillBytes(buf[32:])

	return buf
}

// scalarSubProduct returns (a − b·c) mod N using constant-time modular
// arithmetic, so the operand values do not influence execution time. This
// matters because the response scalar is computed from the proof nonce and the
// secret key; math/big's Mul and Mod are variable-time and would expose both.
//
// The challenge c is public and appears in the proof, so its big.Int form
// carries no secret. The result is likewise published.
func scalarSubProduct(a, b *dcrsecp256k1.ModNScalar, c *big.Int) *big.Int {
	var cBuf [32]byte
	c.FillBytes(cBuf[:])

	var cs, res dcrsecp256k1.ModNScalar
	cs.SetBytes(&cBuf)

	res.Mul2(b, &cs).Negate().Add(a)
	resBytes := res.Bytes()
	res.Zero()

	return new(big.Int).SetBytes(resBytes[:])
}

// nonceRFC6979 deterministically derives the proof nonce k from the secret
// scalar and the hash-to-curve point, following RFC 6979 with HMAC-SHA256. The
// returned scalar lies in [1, N-1] and is a function of its inputs alone, so
// proof generation does not depend on the RNG at call time.
//
// iteration advances the RFC 6979 generator to produce a fresh nonce for the
// same inputs; callers start at 0 and increment only when the resulting proof
// is unusable. The caller owns the returned scalar and should zero it when done.
func nonceRFC6979(secret *dcrsecp256k1.ModNScalar, h *Point, iteration uint32) *dcrsecp256k1.ModNScalar {
	secretBytes := secret.Bytes()
	defer clear(secretBytes[:])

	digest := crypto.Keccak256(encodePointCoordinates(h.X, h.Y))

	return dcrsecp256k1.NonceRFC6979(secretBytes[:], digest, nil, nil, iteration)
}

// HashToZn hashes an arbitrary message to a scalar in Z_N (the secp256k1 group order).
func HashToZn(msg []byte) *big.Int {
	buf := crypto.Keccak256(msg)
	c := new(big.Int).SetBytes(buf)
	c.Mod(c, s256Curve.N) // since N and 2^256 are close, this is a good enough way to hash to Z_N

	return c
}

// HashToCurve hashes a message to a point in the secp256k1 group, salted with
// the public key so that each key is bound to an independent hash-to-curve
// function. Returns nil if no point is found within the iteration bound.
func HashToCurve(pk *ecdsa.PublicKey, msg []byte) *Point {
	buf := crypto.Keccak256(encodePointCoordinates(pk.X, pk.Y), msg)
	x := new(big.Int).SetBytes(buf)
	x.Mod(x, s256Curve.P) // since P and 2^256 are close, this is a good enough way to hash to the curve

	for range 256 {
		// probability of a valid point is ≈ 1/2, so 256 iterations is enough for negligible failure probability
		x3 := new(big.Int).Exp(x, big.NewInt(3), s256Curve.P)
		x3.Add(x3, s256Curve.B)
		x3.Mod(x3, s256Curve.P)

		y := new(big.Int).ModSqrt(x3, s256Curve.P)
		if y != nil {
			return &Point{X: x, Y: y}
		}
		buf = crypto.Keccak256(buf)
		x = new(big.Int).SetBytes(buf)
		x.Mod(x, s256Curve.P)
	}

	return nil
}
