package utils

import (
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
