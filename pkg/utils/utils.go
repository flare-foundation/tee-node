package utils

import (
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	"golang.org/x/exp/constraints"
)

type Number interface {
	constraints.Integer | constraints.Float
}

// Sum calculates the sum of elements in a slice.
func Sum[T Number](numbers []T) T {
	total := T(0)
	for _, num := range numbers {
		total += num
	}

	return total
}

// ConstantSlice crates a slice of length n with all the entries equal to val.
func ConstantSlice[T any](val T, n int) []T {
	res := make([]T, n)
	for i := range n {
		res[i] = val
	}

	return res
}

func CheckCosigners(signers []common.Address, dataProviderIndex map[common.Address]int, allCosigners []common.Address, threshold uint64) ([]bool, error) {
	countCosigners := uint64(0)
	for _, cosigner := range allCosigners {
		if ok := slices.Contains(signers, cosigner); ok {
			countCosigners++
		}
	}

	isSignerCosigner := make([]bool, len(signers))
	for i, signer := range signers {
		isCosigner := slices.Contains(allCosigners, signer)
		_, isDataProvider := dataProviderIndex[signer]
		if !isCosigner && !isDataProvider {
			return nil, errors.New("signed by an entity that is nether data provider nor cosigner")
		}
		isSignerCosigner[i] = isCosigner
	}

	if countCosigners < threshold {
		return nil, errors.New("cosigners threshold not reached")
	}

	return isSignerCosigner, nil
}
