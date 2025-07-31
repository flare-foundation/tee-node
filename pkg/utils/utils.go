package utils

import (
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

type Number interface {
	uint16 | int | float64
}

// Sum calculates the sum of elements in a slice
func Sum[T Number](numbers []T) T {
	total := T(0)
	for _, num := range numbers {
		total += num
	}

	return total
}

func ConstantSlice(val uint16, n int) []uint16 {
	res := make([]uint16, n)
	for i := range n {
		res[i] = val
	}

	return res
}

func CheckCosigners(signers []common.Address, isSignerDataProvider []bool, allCosigners []common.Address, threshold uint64) ([]bool, error) {
	// this should be always false, but just in case
	if len(signers) != len(isSignerDataProvider) {
		return nil, errors.New("number of signers does not match isSignerDataProvider's length")
	}

	countCosigners := uint64(0)
	for _, cosigner := range allCosigners {
		if ok := slices.Contains(signers, cosigner); ok {
			countCosigners++
		}
	}

	isSignerCosigner := make([]bool, len(signers))
	for i, signer := range signers {
		isCosigner := slices.Contains(allCosigners, signer)
		if !isCosigner && !isSignerDataProvider[i] {
			return nil, errors.New("signed by an entity that is nether data provider nor cosigner")
		}
		isSignerCosigner[i] = isCosigner
	}

	if countCosigners < threshold {
		return nil, errors.New("cosigners threshold not reached")
	}

	return isSignerCosigner, nil
}
