package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateSubsets(t *testing.T) {
	tests := []struct {
		nums     []int
		n        int
		expected [][]int
	}{
		{[]int{1, 2, 3}, 2, [][]int{{1, 2}, {1, 3}, {2, 3}}},
		{[]int{1, 2, 3, 4}, 3, [][]int{{1, 2, 3}, {1, 2, 4}, {1, 3, 4}, {2, 3, 4}}},
		{[]int{1, 2, 3}, 1, [][]int{{1}, {2}, {3}}},
		{[]int{1, 2, 3}, 0, [][]int{{}}},
		{[]int{1}, 1, [][]int{{1}}},
	}

	for _, test := range tests {
		result := GenerateSubsets(test.nums, test.n)
		require.Equal(t, test.expected, result)
	}
}
