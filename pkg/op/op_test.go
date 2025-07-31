package op

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestOPTypes(t *testing.T) {
	opTypesOK := []string{
		"F_REG",
		"F_GET",
	}

	for _, opType := range opTypesOK {
		ot, ok := StringToOPTypeSafe(opType)
		require.True(t, ok)

		ok = ot.IsValid()
		require.True(t, ok)

		h := ot.Hash()

		ot2, ok := HashToOPTypeSafe(h)
		require.True(t, ok)

		require.Equal(t, ot, ot2)
		require.Equal(t, opType, string(ot))
	}

	opTypesFail := []string{
		"reg",
		"GET",
	}

	for _, opType := range opTypesFail {
		ot, ok := StringToOPTypeSafe(opType)
		require.False(t, ok)

		ok = ot.IsValid()
		require.False(t, ok)

		h := ot.Hash()

		ot2, ok := HashToOPTypeSafe(h)
		require.False(t, ok)

		require.Equal(t, ot, ot2)
		require.Equal(t, opType, string(ot))
	}
}

func TestSafeVSUnsafe(t *testing.T) {
	s := "randomString"

	_, ok := StringToOPCommandSafe(s)
	require.False(t, ok)
	_, ok = StringToOPTypeSafe(s)
	require.False(t, ok)

	h := []byte(s)
	ch := common.Hash{}

	copy(ch[:len(h)], h)

	_, ok = HashToOPCommandSafe(ch)
	require.False(t, ok)

	_, ok = HashToOPTypeSafe(ch)
	require.False(t, ok)

	c := HashToOPCommand(ch)
	require.Equal(t, s, string(c))

	ty := HashToOPType(ch)
	require.Equal(t, s, string(ty))
}

func TestOPTCommands(t *testing.T) {
	opCommandsOK := []string{
		"PAY",
	}

	for _, opCommands := range opCommandsOK {
		ot, ok := StringToOPCommandSafe(opCommands)
		require.True(t, ok)

		ok = ot.IsValid()
		require.True(t, ok)

		h := ot.Hash()

		ot2, ok := HashToOPCommandSafe(h)
		require.True(t, ok)

		require.Equal(t, ot, ot2)
		require.Equal(t, opCommands, string(ot))
	}

	opCommandsFail := []string{
		"pay",
	}

	for _, opCommands := range opCommandsFail {
		ot, ok := StringToOPCommandSafe(opCommands)
		require.False(t, ok)

		ok = ot.IsValid()
		require.False(t, ok)

		h := ot.Hash()

		ot2, ok := HashToOPCommandSafe(h)
		require.False(t, ok)

		require.Equal(t, ot, ot2)
		require.Equal(t, opCommands, string(ot))
	}
}

func TestValidPair(t *testing.T) {
	ok := IsValidPair(XRP, Reissue)
	require.True(t, ok)

	ok = IsValid(XRP.Hash(), Reissue.Hash())
	require.True(t, ok)

	ok = IsValidPair(Reg, KeyGenerate)
	require.False(t, ok)

	ok = IsValid(Reg.Hash(), KeyGenerate.Hash())
	require.False(t, ok)
}
