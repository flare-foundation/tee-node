package utils

import (
	"crypto/rand"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/pkg/errors"
)

var P = secp256k1.S256().N
var Zero = big.NewInt(0)

type ShamirShare struct {
	X         *big.Int
	Y         *big.Int
	Threshold int
	NumShares int
}

func SplitToShamirShares(val *big.Int, numShares int, threshold int) ([]ShamirShare, error) {
	// Verify minimum isn't greater than shares; there is no way to recreate
	// the original polynomial in our current setup, therefore it doesn't make
	// sense to generate fewer shares than are needed to reconstruct the secret.
	if threshold > numShares {
		return nil, errors.New("num shares smaller than threshold")
	}

	polynomial := make([]*big.Int, threshold)
	polynomial[0] = val
	var err error
	for i := 1; i < threshold; i++ {
		polynomial[i], err = rand.Int(rand.Reader, P)
		if err != nil {
			return nil, err
		}
	}

	shamirShares := make([]ShamirShare, numShares)
	for i := 0; i < numShares; i++ {
		shamirShares[i] = ShamirShare{
			X:         big.NewInt(int64(i + 1)),
			Y:         evalPolynomial(polynomial, big.NewInt(int64(i+1))),
			Threshold: threshold,
			NumShares: numShares,
		}
	}

	return shamirShares, nil
}

func evalPolynomial(polynomial []*big.Int, value *big.Int) *big.Int {
	degree := len(polynomial) - 1
	result := new(big.Int).Set(polynomial[degree])

	for s := degree - 1; s >= 0; s-- {
		result = result.Mul(result, value)
		result = result.Add(result, polynomial[s])
		result = result.Mod(result, P)
	}

	return result
}

// CombineShamirShares joins shares assuming that the threshold is at
// exactly the length of the input.
func CombineShamirShares(shamirShares []ShamirShare) (*big.Int, error) {
	result := big.NewInt(0)

	// Lagrange Interpolation
	for i, share := range shamirShares {
		prod := new(big.Int).Set(share.Y)
		for j, shareJ := range shamirShares {
			if i == j {
				continue
			}
			prod.Mul(prod, shareJ.X)
			denom := new(big.Int).Sub(shareJ.X, share.X)
			if denom.Cmp(Zero) == 0 {
				return nil, errors.New("double share error")
			}
			denom.ModInverse(denom, P)
			prod.Mul(prod, denom)
			prod.Mod(prod, P)
		}

		result.Add(result, prod)
		result.Mod(result, P)
	}

	return result, nil
}
