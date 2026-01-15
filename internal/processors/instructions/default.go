package instructions

import (
	"errors"
	"fmt"
	"os"

	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/tee-node/internal/extension"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/policy"
	"github.com/flare-foundation/tee-node/pkg/processorutils"
	"github.com/flare-foundation/tee-node/pkg/types"
)

type DefaultProcessor struct {
	extensionPort int
	pStorage      *policy.Storage
	iSAndD        node.IdentifierSignerAndDecrypter
}

// NewDefaultProcessor creates a processor that forwards instruction actions to
// the configured extension endpoint.
func NewDefaultProcessor(port int, policyStorage *policy.Storage, iSAndD node.IdentifierSignerAndDecrypter) DefaultProcessor {
	return DefaultProcessor{
		extensionPort: port,
		pStorage:      policyStorage,
		iSAndD:        iSAndD,
	}
}

// Process routes the instruction action to the external extension at threshold
// and crafts the final vote response when the action ends.
func (p DefaultProcessor) Process(a *types.Action) types.ActionResult {
	data, err := processorutils.Parse[instruction.DataFixed](a.Data.Message)
	if err != nil {
		return processorutils.Invalid(a, err)
	}

	signers, _, err := preprocess(a, data, p.pStorage, p.iSAndD.TeeID())
	if err != nil {
		return processorutils.Invalid(a, err)
	}

	switch a.Data.SubmissionTag {
	case types.Threshold:
		result, err := extension.PostActionToExtension(fmt.Sprintf("http://localhost:%d/action", p.extensionPort), a)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return processorutils.DeadlineExceeded(a, err)
			}
			return processorutils.Invalid(a, fmt.Errorf("extension error: %v", err))
		}
		return *result
	case types.End:
		result := types.ActionResult{
			OPType:        data.OPType,
			OPCommand:     data.OPCommand,
			ID:            a.Data.ID,
			SubmissionTag: a.Data.SubmissionTag,
			Status:        1,
			Version:       settings.EncodingVersion,
		}

		msg, err := rewardingData(data, a.Signatures, a.AdditionalVariableMessages, signers, a.Timestamps, []byte{}, p.iSAndD)
		if err != nil {
			return processorutils.Invalid(a, err)
		}
		result.Data = msg
		return result
	default:
		return processorutils.Invalid(a, errors.New("invalid submissionTag"))
	}
}
