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

// SumUint64 returns the sum of the slice elements accumulated in uint64. Unlike
// Sum, which accumulates in the element type and can wrap for narrow types
// (e.g. a []uint16 whose total exceeds 65535), this widens each element so the
// total cannot overflow for any realistic input.
func SumUint64[T constraints.Unsigned](numbers []T) uint64 {
	var total uint64
	for _, num := range numbers {
		total += uint64(num)
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
