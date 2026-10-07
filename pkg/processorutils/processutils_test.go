package processorutils

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/stretchr/testify/require"

	"github.com/flare-foundation/tee-node/pkg/types"
)

func TestFailedResultsCarryOp(t *testing.T) {
	opType, opCommand := op.Type("someOpType").Hash(), op.Command("someOpCommand").Hash()

	tests := []struct {
		name        string
		message     string
		wantType    common.Hash
		wantCommand common.Hash
	}{
		{"valid", `{"opType":"` + opType.Hex() + `","opCommand":"` + opCommand.Hex() + `","message":"0x"}`, opType, opCommand},
		{"other field malformed", `{"opType":"` + opType.Hex() + `","opCommand":"` + opCommand.Hex() + `","message":5}`, opType, opCommand},
		{"op partially decoded", `{"opType":"` + opType.Hex() + `","opCommand":123}`, common.Hash{}, common.Hash{}},
		{"not JSON", `not json`, common.Hash{}, common.Hash{}},
	}

	for _, tc := range tests {
		a := &types.Action{Data: types.ActionData{ID: common.Hash{0x1}, SubmissionTag: types.Submit, Message: []byte(tc.message)}}

		inv := Invalid(a, errors.New("boom"))
		require.Equal(t, uint8(0), inv.Status, tc.name)
		require.Equal(t, tc.wantType, inv.OPType, tc.name)
		require.Equal(t, tc.wantCommand, inv.OPCommand, tc.name)

		de := DeadlineExceeded(a, errors.New("boom"))
		require.Equal(t, uint8(3), de.Status, tc.name)
		require.Equal(t, tc.wantType, de.OPType, tc.name)
		require.Equal(t, tc.wantCommand, de.OPCommand, tc.name)
	}
}
