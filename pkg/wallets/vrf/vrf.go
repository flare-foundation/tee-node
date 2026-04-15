package vrf

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

var (
	one          = big.NewInt(1)
	uint256Ty, _ = abi.NewType("uint256", "uint256", nil)
	s256Curve    = secp256k1.S256()
	arguments    = abi.Arguments{{Type: uint256Ty}, {Type: uint256Ty}, {Type: uint256Ty},
		{Type: uint256Ty}, {Type: uint256Ty}, {Type: uint256Ty},
		{Type: uint256Ty}, {Type: uint256Ty}, {Type: uint256Ty},
		{Type: uint256Ty}, {Type: uint256Ty}, {Type: uint256Ty}}
)

type Point struct {
	X *big.Int
	Y *big.Int
}

// IsOnCurve reports whether the point lies on the secp256k1 curve.
func (p *Point) IsOnCurve() bool {
	return s256Curve.IsOnCurve(p.X, p.Y)
}

func validateScalar(k *big.Int) error {
	if k == nil {
		return errors.New("scalar is nil")
	}
	if k.Cmp(s256Curve.N) >= 0 || k.Sign() <= 0 {
		return errors.New("scalar is not in range [0, N)")
	}
	if len(k.Bytes()) > 32 { // this should never happen
		return errors.New("can't handle scalars > 256 bits")
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
	if err := validateScalar(k); err != nil {
		return nil, err
	}
	bBytes := k.Bytes()

	x, y := s256Curve.ScalarMult(s256Curve.Gx, s256Curve.Gy, bBytes)
	if x == nil || y == nil {
		return nil, errors.New("scalar multiplication failed")
	}

	return &Point{X: x, Y: y}, nil
}

// ScalarMult returns k*P, where P is provided point of the group and k is
// an integer.
func ScalarMult(p *Point, k *big.Int) (*Point, error) {
	if err := p.ValidatePoint(); err != nil {
		return nil, err
	}
	if err := validateScalar(k); err != nil {
		return nil, err
	}
	bBytes := k.Bytes()

	x, y := s256Curve.ScalarMult(p.X, p.Y, bBytes)
	if x == nil || y == nil {
		return nil, errors.New("scalar multiplication failed")
	}

	return &Point{X: x, Y: y}, nil
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
	Gamma *Point   // gamma = sk · HashToCurve(nonce)
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

func validateKey(key *ecdsa.PrivateKey) error {
	if key == nil {
		return errors.New("key is nil")
	}
	if err := validatePublicKey(&key.PublicKey); err != nil {
		return err
	}
	return validateScalar(key.D)
}

// VerifiableRandomness creates a deterministic verifiable randomness (with proof) given a
// private key and a nonce.
func VerifiableRandomness(key *ecdsa.PrivateKey, nonce []byte) (*Proof, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}

	h := HashToCurve(nonce)
	if h == nil {
		return nil, errors.New("failed to hash to curve")
	}
	gamma, err := ScalarMult(h, key.D)
	if err != nil {
		return nil, err
	}

	k, err := rand.Int(rand.Reader, s256Curve.N)
	if err != nil {
		return nil, err
	}

	u, err := ScalarBaseMult(k) // u = k·G  (equals c·pk + s·G after c,s are fixed)
	if err != nil {
		return nil, err
	}
	v, err := ScalarMult(h, k) // v = k·h  (equals c·gamma + s·h after c,s are fixed)
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

	s := new(big.Int).Mul(key.D, c)
	s.Neg(s)
	s.Add(k, s)
	s.Mod(s, s256Curve.N)

	cGamma, err := ScalarMult(gamma, c)
	if err != nil {
		return nil, err
	}

	// ZInv = modInv(cGamma.X − v.X, P).  Skip if denominator is zero.
	denom := new(big.Int).Sub(cGamma.X, v.X)
	denom.Mod(denom, s256Curve.P)
	if denom.Sign() == 0 {
		// This is an extremely unlikely edge case (probability ≈ 1/P) where the proof would be rejected by the contract
		return nil, errors.New("proof generation failed: invalid ZInv denominator")
	}
	zInv := new(big.Int).ModInverse(denom, s256Curve.P)

	return &Proof{Gamma: gamma, C: c, S: s, U: u, CGamma: cGamma, V: v, ZInv: zInv}, nil
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

	h := HashToCurve(nonce)
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
	gammaX := proof.Gamma.X.FillBytes(make([]byte, 32))
	gammaY := proof.Gamma.Y.FillBytes(make([]byte, 32))
	sum := crypto.Keccak256(append(gammaX, gammaY...))

	return common.BytesToHash(sum), nil
}

// HashToZn hashes an arbitrary message to a scalar in Z_N (the secp256k1 group order).
func HashToZn(msg []byte) *big.Int {
	buf := crypto.Keccak256(msg)
	c := new(big.Int).SetBytes(buf)
	c.Mod(c, s256Curve.N) // since N and 2^256 are close, this is a good enough way to hash to Z_N

	return c
}

// HashToCurve hashes an arbitrary message to a point in an elliptic group.
func HashToCurve(msg []byte) *Point {
	buf := crypto.Keccak256(msg)
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
