package utils

import (
	"encoding/binary"
)

// Native values are stored as an integer number of "drips" each representing
// 1/1000000.
type Value struct {
	num uint64
}

func NewValue(num uint64) *Value {
	return &Value{
		num: num,
	}
}

func (v *Value) Bytes() []byte {
	if v == nil {
		return nil
	}
	var u uint64
	u |= 1 << 62
	u |= v.num & ((1 << 62) - 1)

	var b [8]byte
	binary.BigEndian.PutUint64(b[:], u)
	return b[:]
}

// ----------------------------------------

type Amount struct {
	*Value
	Currency Currency
	Issuer   Account
}

// Requires v to be in computer parsable form
func NewAmount(v uint64) *Amount {
	return &Amount{
		Value: NewValue(v),
	}
}

func (a Amount) Bytes() []byte {
	return a.Value.Bytes()
}

// ----------------------------------------

type Currency [20]byte

// ----------------------------------------
type TransactionType uint16
type TransactionFlag uint32

type enc struct {
	typ, field uint8
}

func (e enc) Priority() uint32 {
	return uint32(e.typ)<<16 | uint32(e.field)
}

func (e enc) SigningField() bool {
	_, ok := signingFields[e]
	return ok
}

// ----------------------------------------

type MemoItem struct {
	MemoType   []byte
	MemoData   []byte
	MemoFormat []byte
}

type Memo struct {
	Memo MemoItem
}

type Memos []Memo

// ----------------------------------------

// PathElem represents one link in a path.
type PathElem struct {
	Account  *Account
	Currency *Currency
	Issuer   *Account
}

// Path represents a single path of liquidity that a transaction may use.
type Path []PathElem

// PathSet represents a collection of possible paths that a transaction may use.
type PathSet []Path

// ----------------------------------------

type Hash256 [32]byte
type PublicKey [33]byte
type Account [20]byte

func (h *Hash256) Bytes() []byte {
	if h == nil {
		return nil
	}
	return h[:]
}

// func (v *VariableLength) Bytes() []byte {
// 	if v != nil {
// 		return []byte(*v)
// 	}
// 	return []byte(nil)
// }

func (p *PublicKey) Bytes() []byte {
	if p != nil {
		return p[:]
	}
	return []byte(nil)
}

// Get the address from the sec1 encoded public key
func (p *PublicKey) Address() string {
	account := Sha256RipeMD160(p.Bytes())
	accBytes := append([]byte{0}, account[:]...)

	return Base58Encode(accBytes, ALPHABET)
}

func (a *Account) Bytes() []byte {
	if a != nil {
		return a[:]
	}
	return []byte(nil)
}
