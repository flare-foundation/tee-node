package utils

import (
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

func OpHashToString(hash common.Hash) string {
	return strings.TrimRight(string(hash.Bytes()), "\x00")
}

func StringToOpHash(str string) common.Hash {
	return common.BytesToHash(common.RightPadBytes([]byte(str), 32))
}

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
