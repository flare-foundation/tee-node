package direct

import (
	"context"
	"testing"

	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestDefaultDirectProcessor(t *testing.T) {
	actionResponseChan := make(chan *types.ActionResult, 1)
	signURL := testutils.StartMockSignServer(t, actionResponseChan)
	extensionPort := testutils.StartDummyExtensionServer(t, signURL)

	proc := NewDefaultProcessor(extensionPort)

	action := testutils.BuildMockDirectAction(t, op.Policy, op.InitializePolicy, "dummyAction")
	firstResult := proc.Process(context.Background(), action)
	require.Equal(t, action.Data.ID, firstResult.ID)
	require.Len(t, firstResult.Data, 0)
	require.Equal(t, uint8(2), firstResult.Status)
	require.Equal(t, "action in processing", firstResult.Log)
	require.Equal(t, action.Data.SubmissionTag, firstResult.SubmissionTag)

	finalResult := <-actionResponseChan
	require.Equal(t, action.Data.ID, finalResult.ID)
	require.Equal(t, uint8(1), finalResult.Status)
	require.Equal(t, action.Data.SubmissionTag, finalResult.SubmissionTag)
}
