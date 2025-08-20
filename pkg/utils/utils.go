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

func CheckMatchingCosigners(givenCosigners, cosigners []common.Address, givenThreshold, threshold uint64) error {
	for _, cosigner := range givenCosigners {
		if !slices.Contains(cosigners, cosigner) {
			return errors.New("provided cosigners do not match saved cosigners")
		}
	}
	if len(givenCosigners) != len(cosigners) {
		return errors.New("the number of provided cosigners does not match the number of saved cosigners")
	}
	if int(givenThreshold) != int(threshold) {
		return errors.Errorf("the threshold of provided cosigners does not match the threshold of saved cosigners, %d != %d", givenThreshold, threshold)
	}

	return nil
}
