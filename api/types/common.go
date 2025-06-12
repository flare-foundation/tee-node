package types

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/pkg/errors"
)

type ECDSAPublicKey wallet.PublicKey

// todo: this should be in go-common
func ParsePubKey(key ECDSAPublicKey) (*ecdsa.PublicKey, error) {
	x := new(big.Int).SetBytes(key.X[:])
	y := new(big.Int).SetBytes(key.Y[:])
	check := secp256k1.S256().IsOnCurve(x, y)
	if !check {
		return nil, errors.New("invalid public key bytes")
	}

	return &ecdsa.PublicKey{Curve: secp256k1.S256(), X: x, Y: y}, nil
}

func PubKeyToStruct(key *ecdsa.PublicKey) ECDSAPublicKey {
	var newKey ECDSAPublicKey
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
