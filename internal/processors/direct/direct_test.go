package direct

import (
	"context"
	"errors"
	"testing"

	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestProcessorErrorKeepsOp(t *testing.T) {
	proc := Processor(func(context.Context, *types.DirectInstruction) ([]byte, error) {
		return nil, errors.New("token timeout")
	})
	action := testutils.BuildMockDirectAction(t, op.Type("someOpType"), op.Command("someOpCommand"), "dummyAction")

	res := proc.Process(context.Background(), action)

	require.Equal(t, uint8(0), res.Status)
	require.Equal(t, "token timeout", res.Log)
	require.Equal(t, action.Data.ID, res.ID)
	require.Equal(t, action.Data.SubmissionTag, res.SubmissionTag)
	require.Equal(t, op.Type("someOpType").Hash(), res.OPType)
	require.Equal(t, op.Command("someOpCommand").Hash(), res.OPCommand)
}

// op is reported even when the processor can't parse the rest of the message.
func TestProcessorParseErrorKeepsOp(t *testing.T) {
	proc := Processor(func(context.Context, *types.DirectInstruction) ([]byte, error) {
		return nil, nil
	})
	action := testutils.BuildMockDirectAction(t, op.Type("someOpType"), op.Command("someOpCommand"), "dummyAction")
	action.Data.Message = []byte(`{"opType":"` + op.Type("someOpType").Hash().Hex() + `","opCommand":"` + op.Command("someOpCommand").Hash().Hex() + `","message":5}`)

	res := proc.Process(context.Background(), action)

	require.Equal(t, uint8(0), res.Status)
	require.Contains(t, res.Log, "invalid JSON")
	require.Equal(t, op.Type("someOpType").Hash(), res.OPType)
	require.Equal(t, op.Command("someOpCommand").Hash(), res.OPCommand)
}
