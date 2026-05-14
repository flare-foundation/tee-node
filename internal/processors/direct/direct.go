package direct

import (
	"context"

	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/processorutils"
	"github.com/flare-foundation/tee-node/pkg/types"
)

type Processor func(ctx context.Context, i *types.DirectInstruction) ([]byte, error)

// Process parses the direct instruction and executes the wrapped processor
// function, returning the action result payload.
func (p Processor) Process(ctx context.Context, a *types.Action) types.ActionResult {
	di, err := processorutils.Parse[types.DirectInstruction](a.Data.Message)
	if err != nil {
		return processorutils.Invalid(a, err)
	}

	msg, err := p(ctx, di)
	if err != nil {
		return processorutils.Invalid(a, err)
	}

	result := types.ActionResult{
		ID:            a.Data.ID,
		SubmissionTag: a.Data.SubmissionTag,
		Status:        1,
		Version:       settings.EncodingVersion,
		OPCommand:     di.OPCommand,
		OPType:        di.OPType,
		Data:          msg,
	}

	return result
}
