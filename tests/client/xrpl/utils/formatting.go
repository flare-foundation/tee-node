package utils

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func EncToBytes(e enc) []byte {
	var b []byte
	switch {
	case e.typ < 16 && e.field < 16:
		b = []byte{e.typ<<4 | e.field}
	case e.typ < 16:
		b = []byte{e.typ << 4, e.field}
	case e.field < 16:
		b = []byte{e.field, e.typ}
	default:
		b = []byte{0, e.typ, e.field}
	}
	return b
}

func toBytes(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.BigEndian, v)
	return buf.Bytes(), err
}

func variableLengthToBytes(b []byte) ([]byte, error) {
	n := len(b)
	var header []byte
	switch {
	case n < 0 || n > 918744:
		return nil, fmt.Errorf("unsupported Variable Length encoding: %d", n)
	case n <= 192:
		header = []byte{uint8(n)}
	case n <= 12480:
		n -= 193
		header = []byte{193 + uint8(n>>8), uint8(n)}
	case n <= 918744:
		n -= 12481
		header = []byte{241 + uint8(n>>16), uint8(n >> 8), uint8(n)}
	}
	return append(header, b...), nil
}

func (a *Account) Marshal() ([]byte, error) {
	return variableLengthToBytes(a.Bytes())
}

func (k *PublicKey) Marshal() ([]byte, error) {
	var zeroPublicKey PublicKey
	if *k == zeroPublicKey {
		return variableLengthToBytes([]byte(nil))
	}
	return variableLengthToBytes(k.Bytes())
}
