package utils

import (
	"github.com/ethereum/go-ethereum/common"
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

// ToHash returns Solidity's bytes32(s) ([]byte(s) appended with zeros to length 32)
// String s can be at most 32 characters long, otherwise it is cut.
func ToHash(s string) common.Hash {
	if len(s) > 32 {
		s = s[:32]
	}
	x := [32]byte{}
	copy(x[:], s)

	return x
}
