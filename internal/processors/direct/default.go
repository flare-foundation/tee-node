package direct

import (
	"fmt"
	"os"

	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/tee-node/internal/extension"
	"github.com/flare-foundation/tee-node/pkg/processorutils"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/pkg/errors"
)

type DefaultProcessor struct {
	extensionPort int
}

func NewDefaultProcessor(port int) DefaultProcessor {
	return DefaultProcessor{port}
}

func (p DefaultProcessor) Process(a *types.Action) types.ActionResult {
	di, err := processorutils.Parse[types.DirectInstruction](a.Data.Message)
	if err != nil {
		return processorutils.Invalid(a, err)
	}

	isValid := op.IsValidPair(di.OPType, di.OPCommand)
	if !isValid {
		return processorutils.Invalid(a, errors.New("invalid OPType, OPCommand pair"))
	}

	result, err := extension.PostActionToExtension(fmt.Sprintf("http://localhost:%d/action", p.extensionPort), a)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return processorutils.DeadlineExceeded(a, err)
		}
		return processorutils.Invalid(a, fmt.Errorf("extension error: %v", err))
	}
	result.Status = 2
	result.Data = []byte("successfully posted to extension")

	return *result
}
