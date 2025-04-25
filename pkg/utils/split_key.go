package utils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

func SplitPrivateKey(privateKey *ecdsa.PrivateKey, n int) ([]*ecdsa.PrivateKey, error) {
	if n < 2 {
		return nil, errors.New("number of splits too low")
	}

	keySplits := make([]*big.Int, n)
	var err error
	sum := big.NewInt(0)
	for i := range n - 1 {
		keySplits[i], err = rand.Int(rand.Reader, P)
		if err != nil {
			return nil, err
		}
		sum.Add(sum, keySplits[i])
		sum.Mod(sum, P)
	}
	keySplits[n-1] = new(big.Int).Sub(privateKey.D, sum)
	keySplits[n-1].Mod(keySplits[n-1], P)

	privateKeys := make([]*ecdsa.PrivateKey, n)
	for i := range n {
		privateKeys[i] = crypto.ToECDSAUnsafe(keySplits[i].Bytes())
	}

	return privateKeys, nil
}

func JoinPrivateKeys(privateKeys []*ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
	if len(privateKeys) == 0 {
		return nil, errors.New("no private keys")
	}

	sum := big.NewInt(0)
	for _, key := range privateKeys {
		sum.Add(sum, key.D)
		sum.Mod(sum, P)
	}
	privateKey := crypto.ToECDSAUnsafe(sum.Bytes())

	return privateKey, nil
}
