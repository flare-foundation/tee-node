package policy_test

import (
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/fcc-node/internal/policy"
	"github.com/flare-foundation/fcc-node/internal/testutils"
	"github.com/flare-foundation/fcc-node/pkg/types"
	"github.com/flare-foundation/go-flare-common/pkg/random"
	"github.com/stretchr/testify/require"
)

func randomID(t *testing.T) common.Hash {
	t.Helper()
	id, err := random.Hash()
	require.NoError(t, err)
	return id
}

// activate makes a policy of epochID the active one.
func activate(t *testing.T, storage *policy.Storage, epochID uint32) {
	t.Helper()
	voters, _, _ := testutils.GenerateRandomKeys(t, 3)
	require.NoError(t, storage.SetActiveSigningPolicy(testutils.GenerateRandomPolicyData(t, epochID, voters, testSeed)))
}

func TestRecordInstructionOncePerTag(t *testing.T) {
	storage, _ := setupTestStorage(t)
	id := randomID(t)

	require.NoError(t, storage.RecordInstruction(testEpochID1, id, types.Threshold))
	require.ErrorContains(t, storage.RecordInstruction(testEpochID1, id, types.Threshold), "already accepted with submission tag threshold")

	require.NoError(t, storage.RecordInstruction(testEpochID1, id, types.End))
	require.ErrorContains(t, storage.RecordInstruction(testEpochID1, id, types.End), "already accepted with submission tag end")
	require.ErrorContains(t, storage.RecordInstruction(testEpochID1, id, types.Threshold), "already accepted with submission tag threshold")
}

func TestRecordInstructionEndNeedsThreshold(t *testing.T) {
	storage, _ := setupTestStorage(t)
	id := randomID(t)

	require.ErrorContains(t, storage.RecordInstruction(testEpochID1, id, types.End), "not accepted with submission tag threshold")

	// The rejected End records nothing.
	require.NoError(t, storage.RecordInstruction(testEpochID1, id, types.Threshold))
	require.NoError(t, storage.RecordInstruction(testEpochID1, id, types.End))
}

func TestRecordInstructionRejectsOtherTags(t *testing.T) {
	storage, _ := setupTestStorage(t)
	id := randomID(t)

	for _, tag := range []types.SubmissionTag{types.Submit, "", "THRESHOLD"} {
		require.ErrorContains(t, storage.RecordInstruction(testEpochID1, id, tag), "invalid submission tag")
	}

	// A rejected tag records nothing.
	require.NoError(t, storage.RecordInstruction(testEpochID1, id, types.Threshold))
	require.NoError(t, storage.RecordInstruction(testEpochID1, id, types.End))
}

// TestRecordInstructionAcrossEpochs checks that an ID is accepted once per tag
// even if it is presented with each of the two accepted epochs.
func TestRecordInstructionAcrossEpochs(t *testing.T) {
	storage, _ := setupTestStorage(t)
	activate(t, storage, testEpochID2)
	id := randomID(t)

	require.NoError(t, storage.RecordInstruction(testEpochID1, id, types.Threshold))
	require.ErrorContains(t, storage.RecordInstruction(testEpochID2, id, types.Threshold), "already accepted")

	require.NoError(t, storage.RecordInstruction(testEpochID2, id, types.End))
	require.ErrorContains(t, storage.RecordInstruction(testEpochID1, id, types.End), "already accepted")
}

func TestRecordInstructionDropsOldEpochs(t *testing.T) {
	storage, _ := setupTestStorage(t)
	inFirst, inSecond := randomID(t), randomID(t)

	require.NoError(t, storage.RecordInstruction(testEpochID1, inFirst, types.Threshold))

	// Epochs 1 and 2 are accepted, so the record of epoch 1 is kept.
	activate(t, storage, testEpochID2)
	require.ErrorContains(t, storage.RecordInstruction(testEpochID1, inFirst, types.Threshold), "already accepted")
	require.ErrorContains(t, storage.RecordInstruction(testEpochID2, inFirst, types.Threshold), "already accepted")
	require.NoError(t, storage.RecordInstruction(testEpochID2, inSecond, types.Threshold))

	// Epoch 1 is no longer accepted and its records are dropped.
	activate(t, storage, testEpochID3)
	require.ErrorContains(t, storage.RecordInstruction(testEpochID1, randomID(t), types.Threshold), "instructions of reward epoch 1 not accepted")
	require.NoError(t, storage.RecordInstruction(testEpochID3, inFirst, types.Threshold))
	require.ErrorContains(t, storage.RecordInstruction(testEpochID3, inSecond, types.Threshold), "already accepted")
}

// TestRecordInstructionNeedsActivePolicy checks that the records of an epoch
// start when its signing policy becomes active.
func TestRecordInstructionNeedsActivePolicy(t *testing.T) {
	storage := policy.InitializeStorage()
	require.ErrorContains(t, storage.RecordInstruction(testEpochID1, randomID(t), types.Threshold), "instructions of reward epoch 1 not accepted")

	storage, _ = setupTestStorage(t)
	require.ErrorContains(t, storage.RecordInstruction(testEpochID2, randomID(t), types.Threshold), "instructions of reward epoch 2 not accepted")

	activate(t, storage, testEpochID2)
	require.NoError(t, storage.RecordInstruction(testEpochID2, randomID(t), types.Threshold))
}

func TestRecordInstructionDestroyState(t *testing.T) {
	storage, _ := setupTestStorage(t)
	id := randomID(t)
	require.NoError(t, storage.RecordInstruction(testEpochID1, id, types.Threshold))

	storage.DestroyState()
	require.ErrorContains(t, storage.RecordInstruction(testEpochID1, id, types.Threshold), "instructions of reward epoch 1 not accepted")

	voters, _, pubKeysMap := testutils.GenerateRandomKeys(t, 3)
	initialPolicy := testutils.GenerateRandomPolicyData(t, testEpochID1, voters, testSeed)
	require.NoError(t, storage.SetInitialPolicy(testutils.DefaultTestChainID, initialPolicy, pubKeysMap))
	require.NoError(t, storage.RecordInstruction(testEpochID1, id, types.Threshold))
}

func TestRecordInstructionConcurrent(t *testing.T) {
	storage, _ := setupTestStorage(t)
	id := randomID(t)

	const workers = 32
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Go(func() { errs[i] = storage.RecordInstruction(testEpochID1, id, types.Threshold) })
	}
	wg.Wait()

	accepted := 0
	for _, err := range errs {
		if err == nil {
			accepted++
		}
	}
	require.Equal(t, 1, accepted)
}
