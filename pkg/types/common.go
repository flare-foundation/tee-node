package types

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
)

type OpID struct {
	OPType    common.Hash `json:"opType"`
	OPCommand common.Hash `json:"opCommand"`
}

// GetOpID extracts OpID from the action.
func GetOpID(a *Action) (OpID, error) {
	var id OpID
	err := json.Unmarshal(a.Data.Message, &id)
	return id, err
}

// String returns the textual representation of the operation identifiers.
func (i OpID) String() string {
	return string(op.HashToOPType(i.OPType)) + ", " + string(op.HashToOPCommand(i.OPCommand))
}

// ParsePubKey converts the serialized public key into an ECDSA key.
func ParsePubKey(key PublicKey) (*ecdsa.PublicKey, error) {
	x := new(big.Int).SetBytes(key.X[:])
	y := new(big.Int).SetBytes(key.Y[:])
	check := secp256k1.S256().IsOnCurve(x, y)
	if !check {
		return nil, errors.New("invalid public key bytes")
	}

	return &ecdsa.PublicKey{Curve: secp256k1.S256(), X: x, Y: y}, nil
}

// ParsePubKeyBytes converts key that consists of concatenated X and Y coordinates into an ECDSA public key.
// Key is [X||Y] where X and Y are 32 bytes each.
func ParsePubKeyBytes(key []byte) (*ecdsa.PublicKey, error) {
	if len(key) != 64 {
		return nil, errors.New("invalid public key should be 64 bytes long")
	}
	x := new(big.Int).SetBytes(key[:32])
	y := new(big.Int).SetBytes(key[32:64])
	check := secp256k1.S256().IsOnCurve(x, y)
	if !check {
		return nil, errors.New("coordinates not on curve")
	}

	return &ecdsa.PublicKey{Curve: secp256k1.S256(), X: x, Y: y}, nil
}

// PubKeyToStruct converts an ECDSA public key into the fixed-size struct form.
func PubKeyToStruct(key *ecdsa.PublicKey) PublicKey {
	var newKey PublicKey
	xBytes := key.X.Bytes()
	yBytes := key.Y.Bytes()

	if len(xBytes) < 32 {
		xBytes = append(make([]byte, 32-len(xBytes)), xBytes...)
	}
	if len(yBytes) < 32 {
		yBytes = append(make([]byte, 32-len(yBytes)), yBytes...)
	}

	copy(newKey.X[:], xBytes)
	copy(newKey.Y[:], yBytes)

	return newKey
}

// PubKeyToBytes returns the concatenated x and y coordinates of the key.
func PubKeyToBytes(key *ecdsa.PublicKey) []byte {
	xBytes := key.X.Bytes()
	yBytes := key.Y.Bytes()

	if len(xBytes) < 32 {
		xBytes = append(make([]byte, 32-len(xBytes)), xBytes...)
	}
	if len(yBytes) < 32 {
		yBytes = append(make([]byte, 32-len(yBytes)), yBytes...)
	}

	return append(xBytes, yBytes...)
}
