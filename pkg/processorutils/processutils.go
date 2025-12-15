package processorutils

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/types"
)

type QueueID string

const (
	Main   QueueID = "main"
	Direct QueueID = "direct"
)

type validRequestType interface {
	instruction.DataFixed | types.DirectInstruction
}

func Parse[T validRequestType](message []byte) (*T, error) {
	var maxBodySize int
	switch any(new(T)).(type) {
	case *instruction.DataFixed:
		maxBodySize = settings.MaxInstructionSize
	case *types.DirectInstruction:
		maxBodySize = settings.MaxActionSize
	default:
		return nil, errors.New("invalid request type")
	}

	// Check if the request body size exceeds the limit.
	if len(message) > maxBodySize {
		return nil, errors.New("request too large")
	}

	var req T
	err := json.Unmarshal(message, &req)
	if err != nil {
		return nil, fmt.Errorf("invalid JSON, %v", err)
	}

	return &req, nil
}

// Invalid creates action result for invalid action.
func Invalid(a *types.Action, err error) types.ActionResult {
	return types.ActionResult{
		ID:            a.Data.ID,
		SubmissionTag: a.Data.SubmissionTag,
		Status:        0,
		Version:       settings.EncodingVersion,
		Log:           err.Error(),
	}
}

// DeadlineExceeded creates an action result indicating the extension timed out.
func DeadlineExceeded(a *types.Action, err error) types.ActionResult {
	return types.ActionResult{
		ID:            a.Data.ID,
		SubmissionTag: a.Data.SubmissionTag,
		Status:        3,
		Version:       settings.EncodingVersion,
		Log:           err.Error(),
	}
}

// CheckAndAdapt normalizes variable messages and validates associated arrays.
func CheckAndAdapt(a *types.Action) error {
	if len(a.AdditionalVariableMessages) == 0 {
		a.AdditionalVariableMessages = make([]hexutil.Bytes, len(a.Signatures))
	}

	switch {
	case len(a.Timestamps) != len(a.AdditionalVariableMessages), len(a.Timestamps) != len(a.Signatures):
		return errors.New("unaligned providers' data")
	}

	return nil
}

// CheckMatchingCosigners provided cosigners match the expected cosigners.
func CheckMatchingCosigners(expectedCosigners, cosigners []common.Address, expectedThreshold, threshold uint64) error {
	for _, cosigner := range expectedCosigners {
		if !slices.Contains(cosigners, cosigner) {
			return errors.New("provided cosigners do not match saved cosigners")
		}
	}
	if len(expectedCosigners) != len(cosigners) {
		return errors.New("the number of provided cosigners does not match the number of saved cosigners")
	}
	if expectedThreshold != threshold {
		return fmt.Errorf("the threshold of provided cosigners does not match the threshold of saved cosigners, %d != %d", expectedThreshold, threshold)
	}

	return nil
}
