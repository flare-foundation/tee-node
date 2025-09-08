package direct

import (
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/processorutils"
	"github.com/flare-foundation/tee-node/pkg/types"
)

type Processor func(i *types.DirectInstruction) ([]byte, error)

func (p Processor) Process(a *types.Action) types.ActionResult {
	di, err := processorutils.Parse[types.DirectInstruction](a.Data.Message)
	if err != nil {
		return processorutils.Invalid(a, err)
	}

	msg, err := p(di)
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
