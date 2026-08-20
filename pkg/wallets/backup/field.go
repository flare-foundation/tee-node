package backup

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"filippo.io/bigmod"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"

	"github.com/flare-foundation/tee-node/pkg/utils"
	"github.com/flare-foundation/tee-node/pkg/wallets"
)

// Field is the prime field a wallet's secret is shared over. Secret sharing is
// only injective when every possible secret is smaller than the modulus, so the
// field is selected from the key's metadata rather than fixed globally: a
// secp256k1 scalar is always below the group order, while a raw 32-byte seed is
// not.
//
// ID is recorded in the backup so that reconstruction resolves the same field
// the backup was written with, rather than re-deriving it from a mapping that
// may have changed.
type Field struct {
	ID      common.Hash
	Modulus *bigmod.Modulus

	// modulusInt mirrors Modulus for uniform sampling, which needs an upper
	// bound as an integer.
	modulusInt *big.Int

	// Size is the width in bytes of every field element in serialized form.
	Size int
}

// Field identifiers. These are recorded in backups and must not change value
// once any backup carrying them exists.
var (
	// FieldSecp256k1OrderID covers secrets that are secp256k1 scalars, which
	// are below the group order by construction.
	FieldSecp256k1OrderID = utils.ToHash("secp256k1-group-order")

	// FieldPrimeAbove256ID covers secrets that are arbitrary 32-byte values,
	// such as wallet seeds, which have no upper bound below 2^256.
	FieldPrimeAbove256ID = utils.ToHash("prime-above-2^256")
)

var (
	fieldSecp256k1Order *Field
	fieldPrimeAbove256  *Field

	fieldsByID map[common.Hash]*Field
)

func init() {
	// The smallest prime greater than 2^256, so every 32-byte value is a
	// distinct field element.
	primeAbove256 := new(big.Int).Lsh(big.NewInt(1), 256)
	primeAbove256.Add(primeAbove256, big.NewInt(297))

	fieldSecp256k1Order = mustPrimeField(FieldSecp256k1OrderID, secp256k1.S256().N)
	fieldPrimeAbove256 = mustPrimeField(FieldPrimeAbove256ID, primeAbove256)

	fieldsByID = map[common.Hash]*Field{
		FieldSecp256k1OrderID: fieldSecp256k1Order,
		FieldPrimeAbove256ID:  fieldPrimeAbove256,
	}
}

// mustPrimeField builds a Field and panics if the modulus is unusable. Fields
// are package constants, so a failure here is a programming error rather than
// an input error.
func mustPrimeField(id common.Hash, modulus *big.Int) *Field {
	if modulus.Bit(0) == 0 {
		panic(fmt.Sprintf("backup: field modulus for %s is even", id))
	}
	if !modulus.ProbablyPrime(64) {
		panic(fmt.Sprintf("backup: field modulus for %s is not prime", id))
	}

	size := (modulus.BitLen() + 7) / 8
	m, err := bigmod.NewModulus(modulus.FillBytes(make([]byte, size)))
	if err != nil {
		panic(fmt.Sprintf("backup: invalid field modulus for %s: %v", id, err))
	}

	return &Field{
		ID:         id,
		Modulus:    m,
		modulusInt: new(big.Int).Set(modulus),
		Size:       size,
	}
}

// FieldFor selects the field a key's secret must be shared over. Unknown
// combinations are rejected rather than defaulting, because sharing a secret
// over a field too small for it silently reconstructs a different value.
func FieldFor(keyType, signingAlgo common.Hash) (*Field, error) {
	switch signingAlgo {
	case wallets.EVMSignAlgo, wallets.XRPSignAlgo, wallets.VRFAlgo:
		return fieldSecp256k1Order, nil
	default:
		return nil, fmt.Errorf("no secret sharing field defined for key type %s with signing algorithm %s", keyType, signingAlgo)
	}
}

// FieldForID resolves the field a backup was written with.
func FieldForID(id common.Hash) (*Field, error) {
	field, ok := fieldsByID[id]
	if !ok {
		return nil, fmt.Errorf("unknown secret sharing field %s", id)
	}

	return field, nil
}

// Element converts a secret into a field element, rejecting values the field
// cannot represent injectively.
func (f *Field) Element(b []byte) (*bigmod.Nat, error) {
	if len(b) > f.Size {
		return nil, fmt.Errorf("value of %d bytes exceeds the %d-byte field", len(b), f.Size)
	}

	padded := make([]byte, f.Size)
	copy(padded[f.Size-len(b):], b)
	defer clear(padded)

	n, err := bigmod.NewNat().SetBytes(padded, f.Modulus)
	if err != nil {
		return nil, errors.New("value is not smaller than the field modulus")
	}

	return n, nil
}

// ElementFromUint64 converts a small integer, such as a share index, into a field
// element.
func (f *Field) ElementFromUint64(v uint64) *bigmod.Nat {
	var buf [8]byte
	for i := range 8 {
		buf[7-i] = byte(v >> (8 * i))
	}

	padded := make([]byte, f.Size)
	copy(padded[f.Size-len(buf):], buf[:])

	// A modulus larger than 2^64 cannot overflow on an 8-byte value, and every
	// field defined here exceeds that bound.
	n, err := bigmod.NewNat().SetBytes(padded, f.Modulus)
	if err != nil {
		panic("backup: field modulus smaller than 2^64")
	}

	return n
}

// Bytes serializes a field element to the field's fixed width, so a share's
// encoded length never depends on its value.
func (f *Field) Bytes(n *bigmod.Nat) []byte {
	return n.Bytes(f.Modulus)
}

// Random returns a uniformly distributed field element.
func (f *Field) Random() (*bigmod.Nat, error) {
	v, err := rand.Int(rand.Reader, f.modulusInt)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, f.Size)
	v.FillBytes(buf)
	defer clear(buf)

	return bigmod.NewNat().SetBytes(buf, f.Modulus)
}
