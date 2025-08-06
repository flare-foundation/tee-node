package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSum(t *testing.T) {
	type Z uint16

	testsZ := []struct {
		slice []Z
		eSum  Z
	}{
		{
			slice: []Z{},
			eSum:  0,
		},
		{
			slice: []Z{1, 2, 3, 4},
			eSum:  10,
		},
	}

	for _, test := range testsZ {
		require.Equal(t, test.eSum, Sum(test.slice))
	}

	type M int64
	testsM := []struct {
		slice []M
		eSum  M
	}{
		{
			slice: []M{},
			eSum:  0,
		},
		{
			slice: []M{1, 2, 3, 4},
			eSum:  10,
		},
		{
			slice: []M{-1},
			eSum:  -1,
		},
		{
			slice: []M{-1, 1},
			eSum:  0,
		},
	}

	for _, test := range testsM {
		require.Equal(t, test.eSum, Sum(test.slice))
	}

	type F float64
	testsF := []struct {
		slice []F
		eSum  F
	}{
		{
			slice: []F{},
			eSum:  0,
		},
		{
			slice: []F{1, 2, 3, 4},
			eSum:  10,
		},
		{
			slice: []F{-1},
			eSum:  -1,
		},
		{
			slice: []F{-1, 1},
			eSum:  0,
		},
		{
			slice: []F{0.5, 0.5},
			eSum:  1,
		},
	}

	for _, test := range testsF {
		require.Equal(t, test.eSum, Sum(test.slice))
	}
}

func TestConstantSlice(t *testing.T) {
	x := ConstantSlice("a", 10)
	require.Len(t, x, 10)

	require.Equal(t, "a", x[3])
}
