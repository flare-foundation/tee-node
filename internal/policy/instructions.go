package policy

import (
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/tee-node/pkg/types"
)

// acceptedInstructions records the instructions accepted by the node, so that
// an instruction ID is accepted once with the Threshold tag and then once with
// the End tag. An ID is absent until it is accepted at threshold, then maps to
// false, and to true once it is accepted at end.
//
// Records are grouped by the reward epoch of the signing policy the instruction
// references.
type acceptedInstructions struct {
	mu     sync.Mutex
	epochs map[uint32]map[common.Hash]bool
}

// record marks the instruction id of epochID as accepted with tag. Threshold
// is accepted if id is not recorded under any retained epoch, End if id is
// recorded as accepted at threshold only. It fails for any other tag, or if
// the group of epochID does not exist.
func (ai *acceptedInstructions) record(epochID uint32, id common.Hash, tag types.SubmissionTag) error {
	if tag != types.Threshold && tag != types.End {
		return fmt.Errorf("invalid submission tag %q", tag)
	}

	ai.mu.Lock()
	defer ai.mu.Unlock()

	// The caller checks the epoch against the active policy before verifying
	// the signatures. A newer policy may have become active since then and the
	// group of epochID been dropped.
	epochRecords, ok := ai.epochs[epochID]
	if !ok {
		return fmt.Errorf("instructions of reward epoch %d not accepted", epochID)
	}

	var records map[common.Hash]bool
	var ended bool
	for _, r := range ai.epochs {
		if ended, ok = r[id]; ok {
			records = r
			break
		}
	}

	switch {
	case tag == types.Threshold && records != nil:
		return fmt.Errorf("instruction %s already accepted with submission tag %s", id.Hex(), types.Threshold)
	case tag == types.Threshold:
		epochRecords[id] = false
	case records == nil:
		return fmt.Errorf("instruction %s not accepted with submission tag %s", id.Hex(), types.Threshold)
	case ended:
		return fmt.Errorf("instruction %s already accepted with submission tag %s", id.Hex(), types.End)
	default:
		records[id] = true
	}

	return nil
}

// startEpoch creates the group of activeEpochID, whose policy has become
// active, and drops the groups of the epochs whose instructions are no longer
// accepted.
func (ai *acceptedInstructions) startEpoch(activeEpochID uint32) {
	minEpoch := OldestAcceptedEpoch(activeEpochID)

	ai.mu.Lock()
	defer ai.mu.Unlock()

	if ai.epochs == nil {
		ai.epochs = make(map[uint32]map[common.Hash]bool)
	}
	for epochID := range ai.epochs {
		if epochID < minEpoch {
			delete(ai.epochs, epochID)
		}
	}
	if _, ok := ai.epochs[activeEpochID]; !ok {
		ai.epochs[activeEpochID] = make(map[common.Hash]bool)
	}
}

// reset drops all records.
func (ai *acceptedInstructions) reset() {
	ai.mu.Lock()
	defer ai.mu.Unlock()

	ai.epochs = nil
}
