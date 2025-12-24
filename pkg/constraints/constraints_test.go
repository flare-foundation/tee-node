package constraints

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/stretchr/testify/assert"
)

func testConstraintError(t *testing.T, hash common.Hash) {
	t.Helper()
	_, err := constraints(hash)
	assert.Error(t, err)
}

func assertConstraintEqual(t *testing.T, hash common.Hash, expected sizeConstraint) {
	t.Helper()
	got, err := constraints(hash)
	assert.NoError(t, err)
	assert.Equal(t, expected, got)
}

func TestConstraints(t *testing.T) {
	t.Run("non instruction opCommand", func(t *testing.T) {
		testConstraintError(t, op.InitializePolicy.Hash())
		testConstraintError(t, op.UpdatePolicy.Hash())
		testConstraintError(t, op.KeyInfo.Hash())
		testConstraintError(t, op.TEEInfo.Hash())
		testConstraintError(t, op.TEEBackup.Hash())
	})
	t.Run("restore constraint: KeyDataProviderRestore", func(t *testing.T) {
		got, err := constraints(op.KeyDataProviderRestore.Hash())
		assert.NoError(t, err)
		assert.Equal(t, restore, got)
	})

	t.Run("no additional: Pay", func(t *testing.T) {
		assertConstraintEqual(t, op.Pay.Hash(), noAdditional)
		assertConstraintEqual(t, op.Reissue.Hash(), noAdditional)
		assertConstraintEqual(t, op.TEEAttestation.Hash(), noAdditional)
		assertConstraintEqual(t, op.KeyGenerate.Hash(), noAdditional)
		assertConstraintEqual(t, op.KeyDelete.Hash(), noAdditional)
	})

	t.Run("default constraint: Prove", func(t *testing.T) {
		assertConstraintEqual(t, op.Prove.Hash(), defaultConstraint)
		assertConstraintEqual(t, common.HexToHash("0xfffffff"), defaultConstraint)
	})
}

func makeDataFixed(opCmd op.Command, origLen, addFixedLen int) *instruction.DataFixed {
	return &instruction.DataFixed{
		OPCommand:              opCmd.Hash(),
		OriginalMessage:        make([]byte, origLen),
		AdditionalFixedMessage: make([]byte, addFixedLen),
	}
}

func TestCheckSize(t *testing.T) {
	t.Run("returns error for non-instruction op", func(t *testing.T) {
		data := makeDataFixed(op.InitializePolicy, 1, 1)
		err := CheckSize(data)
		assert.Error(t, err)
	})

	t.Run("original message too big", func(t *testing.T) {
		data := makeDataFixed(op.Prove, defaultConstraint.originalMessage+1, 1)
		err := CheckSize(data)
		assert.EqualError(t, err, "original message too big")
	})

	t.Run("additional fixed message too big", func(t *testing.T) {
		data := makeDataFixed(op.Prove, 1, defaultConstraint.additionalFixedMessage+1)
		err := CheckSize(data)
		assert.EqualError(t, err, "additional fixed message message too big")
	})

	t.Run("all within limits", func(t *testing.T) {
		data := makeDataFixed(op.Pay, noAdditional.originalMessage, noAdditional.additionalFixedMessage)
		err := CheckSize(data)
		assert.NoError(t, err)
	})

	t.Run("CheckSize on restore op", func(t *testing.T) {
		// within limits
		data := makeDataFixed(op.KeyDataProviderRestore, restore.originalMessage, restore.additionalFixedMessage)
		err := CheckSize(data)
		assert.NoError(t, err)

		// original message too big
		data = makeDataFixed(op.KeyDataProviderRestore, restore.originalMessage+1, 0)
		err = CheckSize(data)
		assert.EqualError(t, err, "original message too big")

		// additional fixed message too big
		data = makeDataFixed(op.KeyDataProviderRestore, 0, restore.additionalFixedMessage+1)
		err = CheckSize(data)
		assert.EqualError(t, err, "additional fixed message message too big")
	})
}

func TestCheckSizeVariableMessages(t *testing.T) {
	makeVarMsgs := func(nsizes ...int) []hexutil.Bytes {
		var v []hexutil.Bytes
		for _, sz := range nsizes {
			v = append(v, make([]byte, sz))
		}
		return v
	}

	t.Run("returns error for non-instruction op", func(t *testing.T) {
		err := CheckSizeVariableMessages(op.InitializePolicy.Hash(), nil)
		assert.Error(t, err)
	})

	t.Run("empty variableMessages", func(t *testing.T) {
		err := CheckSizeVariableMessages(op.Prove.Hash(), []hexutil.Bytes{})
		assert.NoError(t, err)
	})

	t.Run("defaultConstraint", func(t *testing.T) {
		msgs := makeVarMsgs(
			defaultConstraint.additionalVariableMessage,
			defaultConstraint.additionalVariableMessage-1,
		)
		err := CheckSizeVariableMessages(op.Prove.Hash(), msgs)
		assert.NoError(t, err)

		// variable message too big
		msgs = makeVarMsgs(
			defaultConstraint.additionalVariableMessage + 1,
		)
		err = CheckSizeVariableMessages(op.Prove.Hash(), msgs)
		assert.EqualError(t, err, "additional variable message message too big")
	})

	t.Run("restore", func(t *testing.T) {
		msgs := makeVarMsgs(restore.additionalVariableMessage)
		err := CheckSizeVariableMessages(op.KeyDataProviderRestore.Hash(), msgs)
		assert.NoError(t, err)

		// variable message too big
		msgs = makeVarMsgs(restore.additionalVariableMessage + 1)
		err = CheckSizeVariableMessages(op.KeyDataProviderRestore.Hash(), msgs)
		assert.EqualError(t, err, "additional variable message message too big")
	})

	t.Run("noAdditional", func(t *testing.T) {
		msgs := makeVarMsgs()
		err := CheckSizeVariableMessages(op.Pay.Hash(), msgs)
		assert.NoError(t, err)

		// variable message too big
		msgs = makeVarMsgs(1)
		err = CheckSizeVariableMessages(op.Pay.Hash(), msgs)
		assert.EqualError(t, err, "additional variable message message too big")
	})

	t.Run("unknown op", func(t *testing.T) {
		msgs := makeVarMsgs(defaultConstraint.additionalVariableMessage)
		err := CheckSizeVariableMessages(common.HexToHash("0xffffff"), msgs)
		assert.NoError(t, err)

		// variable message too big
		msgs = makeVarMsgs(defaultConstraint.additionalVariableMessage + 1)
		err = CheckSizeVariableMessages(common.HexToHash("0xffffff"), msgs)
		assert.EqualError(t, err, "additional variable message message too big")
	})
}
