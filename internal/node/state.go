package node

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flare-foundation/go-flare-common/pkg/logger"

	"github.com/flare-foundation/tee-node/internal/extension"
	"github.com/flare-foundation/tee-node/pkg/types"
)

// State supplies the node state carried in the attested TEE info response.
type State interface {
	// State encodes the node state into its serialized representation.
	State() (types.TeeState, error)
}

// ZeroState reports an empty state. It is the state of a node running without
// an extension, where there is nothing to report.
type ZeroState struct{}

// State returns the zero-value node state.
func (ZeroState) State() (types.TeeState, error) {
	return types.TeeState{
		SystemState:        hexutil.Bytes{},
		SystemStateVersion: common.Hash{},
		State:              hexutil.Bytes{},
		StateVersion:       common.Hash{},
	}, nil
}

// ExtensionState reads the state from the extension's /state route on every
// call, so the attested state reflects the extension at the time the TEE info
// response is produced rather than at startup.
type ExtensionState struct {
	url string
}

// NewExtensionState builds a State served by the extension listening on port.
func NewExtensionState(port int) ExtensionState {
	return ExtensionState{url: fmt.Sprintf("http://localhost:%d/state", port)}
}

// State fetches the extension's state.
//
// An unreachable or malformed /state route does not fail the caller: the state
// is one field of a TEE info response that also carries attestation and signing
// policy data, and an extension that is down or mid-restart should not prevent
// the node from being attested. Instead the failure is reported in the state
// itself, with StateVersion set to types.StateUnavailableVersion so a consumer
// can tell an unreadable extension from one that has no state.
func (e ExtensionState) State() (types.TeeState, error) {
	state, err := extension.FetchState(e.url)
	if err != nil {
		logger.Errorf("extension state: %v", err)

		return types.TeeState{
			SystemState:        hexutil.Bytes{},
			SystemStateVersion: common.Hash{},
			State:              hexutil.Bytes{},
			StateVersion:       types.StateUnavailableVersion,
		}, nil
	}

	return state, nil
}
