package router

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	cwallet "github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/processorutils"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/wallets"
	"github.com/stretchr/testify/require"
)

func TestRoutID(t *testing.T) {
	tests := []struct {
		opt op.Type
		opc op.Command
	}{
		{
			opt: op.FDC2,
			opc: op.Prove,
		},
		{
			opt: "",
			opc: "",
		},
		{
			opt: "a",
			opc: "a",
		},
	}

	for j, test := range tests {
		da := testutils.BuildMockDirectAction(t, test.opt, test.opc, nil)

		opID, err := types.GetOpID(da)
		require.NoError(t, err, j)

		require.Equal(t, test.opt.Hash(), opID.OPType)
		require.Equal(t, test.opc.Hash(), opID.OPCommand)
	}
}

func TestRouterDirectActionRouting(t *testing.T) {
	testNode, ps, ws := testutils.Setup(t)

	r := NewPMWRouter(testNode, ws, ps, &settings.ProxyURLMutex{})

	// Create a direct action
	action := testutils.BuildMockDirectAction(t, op.Get, op.TEEInfo, types.TeeInfoRequest{
		Challenge: common.Hash{0x1},
	})

	result := r.process(context.Background(), action, processorutils.Main)

	// Verify results
	require.Equal(t, uint8(1), result.Status)
	require.Equal(t, action.Data.ID, result.ID)
	require.Equal(t, action.Data.ID, result.ID)
}

func TestRouterInstructionActionRoutingThreshold(t *testing.T) {
	// Initialize node for testing
	teeNode, ps, ws := testutils.Setup(t)

	numVoters, randSeed, epochID := 100, int64(12345), uint32(1)
	_, _, providerPrivKeys := testutils.GenerateAndSetInitialPolicy(t, ps, numVoters, randSeed, epochID)

	r := NewPMWRouter(teeNode, ws, ps, &settings.ProxyURLMutex{})

	// Create an instruction action with Threshold submission tag
	teeID := teeNode.TeeID()
	walletID := common.HexToHash("0xabcdef")
	keyID := uint64(1)

	numAdmins := 3
	adminPubKeys := make([]cwallet.PublicKey, numAdmins)
	adminPrivKeys := make([]*ecdsa.PrivateKey, numAdmins)
	var err error
	for i := range numAdmins {
		adminPrivKeys[i], err = crypto.GenerateKey()
		require.NoError(t, err)

		pk := types.PubKeyToStruct(&adminPrivKeys[i].PublicKey)
		adminPubKeys[i] = cwallet.PublicKey{
			X: pk.X,
			Y: pk.Y,
		}
	}

	// Create a proper KeyGenerate message
	originalMessage := cwallet.IWalletKeyManagerKeyGenerate{
		TeeId:       teeID,
		WalletId:    walletID,
		KeyId:       keyID,
		KeyType:     wallets.XRPType,
		SigningAlgo: wallets.XRPSignAlgo,
		ConfigConstants: cwallet.IWalletKeyManagerKeyConfigConstants{
			AdminsPublicKeys:   adminPubKeys,
			AdminsThreshold:    1,
			Cosigners:          make([]common.Address, 0),
			CosignersThreshold: 0,
		},
	}

	// Encode the message properly
	originalMessageEncoded, err := abi.Arguments{cwallet.MessageArguments[op.KeyGenerate]}.Pack(originalMessage)
	require.NoError(t, err)

	action := testutils.BuildMockInstructionAction(
		t,
		op.Wallet,
		op.KeyGenerate,
		originalMessageEncoded,
		providerPrivKeys,
		teeNode.Info().ChainID,
		teeID,
		epochID,
		nil, nil, nil,
		0,
		types.Threshold,
		1234567890,
	)

	// Process the action
	result := r.process(context.Background(), action, processorutils.Main)

	// Verify results
	require.Equal(t, uint8(1), result.Status)
	require.Equal(t, action.Data.ID, result.ID)
	require.Equal(t, types.Threshold, result.SubmissionTag)
}

func TestRouterUnregisteredExtension(t *testing.T) {
	testNode, ps, ws := testutils.Setup(t)
	r := NewPMWRouter(testNode, ws, ps, &settings.ProxyURLMutex{})

	// Create a direct action for an unregistered extension (no processor registered)
	action := testutils.BuildMockDirectAction(t, op.Type("UnregisteredExt"), op.Command("UnregisteredCmd"), nil)

	// Process the action - should fail
	result := r.process(context.Background(), action, processorutils.Main)

	// Verify failure
	require.Equal(t, uint8(0), result.Status)
	require.Contains(t, result.Log, "processor for UnregisteredExt, UnregisteredCmd not registered")
}

func TestRouterExtensionStartingWithF_NotConfigured(t *testing.T) {
	testNode, ps, ws := testutils.Setup(t)
	r := NewForwardRouter(testNode, ws, ps, 8001, &settings.ProxyURLMutex{})

	// Create a direct action for extension starting with F_ but not configured
	action := testutils.BuildMockDirectAction(t, op.Type("F_CustomExtension"), op.Command("CustomCommand"), nil)

	// Process the action - should fail since no processor is registered
	result := r.process(context.Background(), action, processorutils.Main)

	require.Equal(t, uint8(0), result.Status)
	require.Contains(t, result.Log, "invalid OPType, OPCommand pair")
}

// * ================================================================================================ *

// TestRouterRun verifies that the Run function spawns a goroutine for Main queue
// and blocks on Direct queue processing.
func TestRouterRun(t *testing.T) {
	testNode, ps, ws := testutils.Setup(t)

	proxyURL := &settings.ProxyURLMutex{URL: "http://localhost:9999"}
	r := NewPMWRouter(testNode, ws, ps, proxyURL)

	// r.Run spawns ServeQueue goroutines with no cancellation hook, so they keep
	// running past this test. Clearing the proxy URL on test exit makes each
	// subsequent iteration short-circuit at the empty-URL check in
	// serveQueueIteration and sleep silently instead of spamming
	// "connection refused" logs into every later test in this package.
	defer func() {
		proxyURL.Lock()
		proxyURL.URL = ""
		proxyURL.Unlock()
	}()

	// Run in a goroutine since it blocks on Direct queue
	go r.Run(testNode)

	// Wait a bit to ensure the function starts without crashing
	time.Sleep(50 * time.Millisecond)

	// The test passes if Run doesn't crash and starts both goroutines
}

// TestServeQueueBasic tests the basic functionality of ServeQueue with a successful action processing flow.
func TestServeQueueBasic(t *testing.T) {
	testNode, ps, ws := testutils.Setup(t)
	r := NewPMWRouter(testNode, ws, ps, &settings.ProxyURLMutex{})

	// Create a mock action
	action := testutils.BuildMockDirectAction(t, op.Get, op.TEEInfo, types.TeeInfoRequest{
		Challenge: common.Hash{0x1},
	})

	// Track if the result was posted
	resultPosted := make(chan bool, 1)

	// Set up mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/queue/main":
			// Return the mock action
			response, err := json.Marshal(action)
			require.NoError(t, err)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(response)
		case "/result":
			// Verify the response was posted
			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)

			var actionResponse types.ActionResponse
			err = json.Unmarshal(body, &actionResponse)
			require.NoError(t, err)

			// Verify the response structure
			require.Equal(t, action.Data.ID, actionResponse.Result.ID)
			require.NotEmpty(t, actionResponse.Signature)
			resultPosted <- true
		}
	}))
	defer server.Close()

	// Set the proxy URL
	proxyURL := &settings.ProxyURLMutex{URL: server.URL}
	r.proxyURL = proxyURL

	// Registered AFTER `defer server.Close()` so LIFO ordering runs this first:
	// the goroutine sees the empty URL and short-circuits before the server is
	// closed, avoiding "connection refused" log spam in subsequent tests.
	defer func() {
		proxyURL.Lock()
		proxyURL.URL = ""
		proxyURL.Unlock()
	}()

	// Run ServeQueue in a goroutine with a timeout
	go func() {
		r.ServeQueue(processorutils.Main, testNode)
	}()

	// Wait for the result to be posted (with timeout)
	select {
	case <-resultPosted:
		// Processing completed successfully
	case <-time.After(2 * time.Second):
		t.Fatal("ServeQueue did not process action within timeout")
	}
}

// TestServeQueueEmptyProxyURL tests that ServeQueue handles empty proxy URL correctly by sleeping.
func TestServeQueueEmptyProxyURL(t *testing.T) {
	testNode, ps, ws := testutils.Setup(t)
	// Create router with empty proxy URL (forces sleep at first)
	proxyMutex := &settings.ProxyURLMutex{URL: ""}
	r := NewPMWRouter(testNode, ws, ps, proxyMutex)

	// Prepare a mock action to be served if/when proxy URL becomes available
	action := testutils.BuildMockDirectAction(t, op.Get, op.TEEInfo, types.TeeInfoRequest{
		Challenge: common.Hash{0x1},
	})

	// Used to track if the action is fetched/processed
	actionFetched := make(chan bool, 1)
	resultPosted := make(chan bool, 1)

	// Start mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/queue/main":
			resp, err := json.Marshal(action)
			require.NoError(t, err)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(resp)
			actionFetched <- true
		case "/result":
			// Only signal posting, don't check body for this test
			resultPosted <- true
		default:
			t.Errorf("unexpected path called: %s", req.URL.Path)
		}
	}))
	defer server.Close()

	// Registered AFTER `defer server.Close()` so LIFO ordering runs this first:
	// goroutine sees empty URL and short-circuits before the server is closed.
	defer func() {
		proxyMutex.Lock()
		proxyMutex.URL = ""
		proxyMutex.Unlock()
	}()

	// Use a short sleep time for faster tests, set on this router instance so no
	// shared package-level state is mutated (which previously raced the workers).
	const sleepTime = 500 * time.Millisecond
	r.sleepTime = sleepTime

	// Run ServeQueue in a goroutine
	go func() {
		r.ServeQueue(processorutils.Main, testNode)
	}()

	// Wait less than sleep time, verify action is NOT yet fetched
	select {
	case <-actionFetched:
		t.Fatal("action should not be fetched while proxy URL is empty")
	case <-time.After(sleepTime / 2):
		// Expected: no action fetched yet
		break
	}

	time.Sleep(sleepTime)

	r.proxyURL.Lock()
	r.proxyURL.URL = server.URL
	r.proxyURL.Unlock()

	select {
	case <-actionFetched:
		// Expected: action fetched after proxy URL is set
		break
	case <-time.After(sleepTime * 2):
		t.Fatal("action was not fetched after proxy URL set")
	}
}

// * ================================================================================================ *

// TestRegisterProcessorDuplicate tests that registering a duplicate processor panics.
func TestRegisterProcessorDuplicate(t *testing.T) {
	testNode, ps, ws := testutils.Setup(t)
	r := NewPMWRouter(testNode, ws, ps, &settings.ProxyURLMutex{})

	// Create a mock processor
	mockProcessor := ProcessFunc(func(_ context.Context, a *types.Action) types.ActionResult {
		return types.ActionResult{Status: 1}
	})

	// Register the processor first time - should succeed
	r.RegisterProcessor(op.Type("TestType"), op.Command("TestCommand"), mockProcessor)

	// Register the same processor again - should panic
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		r.RegisterProcessor(op.Type("TestType"), op.Command("TestCommand"), mockProcessor)
	}()

	require.True(t, panicked, "Expected panic when registering duplicate processor")
}

// TestRegisterDefaultDirectDuplicate tests that registering a duplicate default direct processor panics.
func TestRegisterDefaultDirectDuplicate(t *testing.T) {
	testNode, ps, ws := testutils.Setup(t)
	r := NewPMWRouter(testNode, ws, ps, &settings.ProxyURLMutex{})

	// Create a mock processor
	mockProcessor := ProcessFunc(func(_ context.Context, a *types.Action) types.ActionResult {
		return types.ActionResult{Status: 1}
	})

	// Register the default direct processor first time - should succeed
	r.RegisterDefaultDirect(mockProcessor)

	// Register the same processor again - should panic
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		r.RegisterDefaultDirect(mockProcessor)
	}()

	require.True(t, panicked, "Expected panic when registering duplicate default direct processor")
}

// TestRegisterDefaultInstructionDuplicate tests that registering a duplicate default instruction processor panics.
func TestRegisterDefaultInstructionDuplicate(t *testing.T) {
	testNode, ps, ws := testutils.Setup(t)
	r := NewPMWRouter(testNode, ws, ps, &settings.ProxyURLMutex{})

	// Create a mock processor
	mockProcessor := ProcessFunc(func(_ context.Context, a *types.Action) types.ActionResult {
		return types.ActionResult{Status: 1}
	})

	// Register the default instruction processor first time - should succeed
	r.RegisterDefaultInstruction(mockProcessor)

	// Register the same processor again - should panic
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		r.RegisterDefaultInstruction(mockProcessor)
	}()

	require.True(t, panicked, "Expected panic when registering duplicate default instruction processor")
}

// TestProcessDefaultInstruction tests the default instruction processor path.
func TestProcessDefaultInstruction(t *testing.T) {
	testNode, ps, ws := testutils.Setup(t)
	r := NewPMWRouter(testNode, ws, ps, &settings.ProxyURLMutex{})

	// Create a mock default instruction processor
	mockProcessor := ProcessFunc(func(_ context.Context, a *types.Action) types.ActionResult {
		return types.ActionResult{
			ID:     a.Data.ID,
			Status: 1,
			Log:    "processed by default instruction processor",
		}
	})

	// Register the default instruction processor
	r.RegisterDefaultInstruction(mockProcessor)

	// Create an instruction action with an unregistered opType/opCommand
	action := testutils.BuildMockInstructionAction(
		t,
		op.Type("UnregisteredType"), op.Command("UnregisteredCommand"),
		[]byte("test message"),
		[]*ecdsa.PrivateKey{}, // Empty private keys for this test
		testNode.Info().ChainID,
		testNode.TeeID(),
		1, // rewardEpochID
		nil, nil, nil, 0,
		types.Threshold,
		1234567890,
	)

	// Process the action
	result := r.process(context.Background(), action, processorutils.Main)

	// Verify the result was processed by the default instruction processor
	require.Equal(t, uint8(1), result.Status)
	require.Equal(t, action.Data.ID, result.ID)
	require.Equal(t, "processed by default instruction processor", result.Log)
}

// TestProcessCheckAndAdaptError tests the processorutils.CheckAndAdapt error handling.
func TestProcessCheckAndAdaptError(t *testing.T) {
	testNode, ps, ws := testutils.Setup(t)
	r := NewPMWRouter(testNode, ws, ps, &settings.ProxyURLMutex{})

	// Create an action with misaligned arrays to trigger CheckAndAdapt error
	action := &types.Action{
		Data: types.ActionData{
			ID:            common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
			Type:          types.Instruction,
			SubmissionTag: types.Threshold,
			Message:       []byte(`{"opType":"0x123","opCommand":"0x456"}`),
		},
		AdditionalVariableMessages: []hexutil.Bytes{[]byte("msg1")},                 // 1 message
		Timestamps:                 []uint64{1234567890, 1234567891},                // 2 timestamps - MISALIGNED
		Signatures:                 []hexutil.Bytes{[]byte("sig1"), []byte("sig2")}, // 2 signatures
	}

	// Process the action
	result := r.process(context.Background(), action, processorutils.Main)

	// Verify the result indicates an error
	require.Equal(t, uint8(0), result.Status)
	require.Equal(t, action.Data.ID, result.ID)
	require.Contains(t, result.Log, "unaligned providers' data")
}

// TestProcessRoutIDError tests the routID error handling.
func TestProcessRoutIDError(t *testing.T) {
	testNode, ps, ws := testutils.Setup(t)
	r := NewPMWRouter(testNode, ws, ps, &settings.ProxyURLMutex{})

	// Create an action with invalid JSON in the message to trigger routID error
	action := &types.Action{
		Data: types.ActionData{
			ID:            common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
			Type:          types.Direct,
			SubmissionTag: types.Submit,
			Message:       []byte(`invalid json`), // Invalid JSON
		},
		AdditionalVariableMessages: []hexutil.Bytes{},
		Timestamps:                 []uint64{},
		Signatures:                 []hexutil.Bytes{},
	}

	// Process the action
	result := r.process(context.Background(), action, processorutils.Main)

	// Verify the result indicates an error
	require.Equal(t, uint8(0), result.Status)
	require.Equal(t, action.Data.ID, result.ID)
	require.Contains(t, result.Log, "invalid character")
}

// shrinkActionTimeouts swaps the package-level action timeouts to small values
// for the duration of a test and restores them on cleanup. Both settings are
// declared as var precisely so tests can override them without changing
// production behavior.
func shrinkActionTimeouts(t *testing.T, processTimeout, drainTimeout time.Duration) {
	t.Helper()
	origProcess := settings.ActionProcessTimeout
	origDrain := settings.ActionDrainTimeout
	settings.ActionProcessTimeout = processTimeout
	settings.ActionDrainTimeout = drainTimeout
	t.Cleanup(func() {
		settings.ActionProcessTimeout = origProcess
		settings.ActionDrainTimeout = origDrain
	})
}

// timeoutTestAction returns a minimal Action that the timeout tests can feed
// straight to processWithTimeout; the routing layer is bypassed by registering
// the test processor on op.FDC2/op.Prove so r.process picks it up.
func timeoutTestAction() *types.Action {
	return &types.Action{
		Data: types.ActionData{
			ID:   common.HexToHash("0xdeadbeef"),
			Type: types.Direct,
			Message: func() []byte {
				di := types.DirectInstruction{OPType: op.FDC2.Hash(), OPCommand: op.Prove.Hash()}
				b, _ := json.Marshal(di)
				return b
			}(),
		},
	}
}

// TestProcessWithTimeout_CooperativeProcessor verifies that when a processor
// follows the production pattern — do work, then gate on ctx.Err() before
// "committing" state — the worker returns the processor's own ctx-cancelled
// error and unblocks well before the drain window expires. This mirrors the
// guard at e.g. walletutils/processor.go KeyGenerate just before wStorage.Store.
func TestProcessWithTimeout_CooperativeProcessor(t *testing.T) {
	shrinkActionTimeouts(t, 100*time.Millisecond, 500*time.Millisecond)

	testNode, ps, ws := testutils.Setup(t)
	r := NewPMWRouter(testNode, ws, ps, &settings.ProxyURLMutex{})

	cooperative := ProcessFunc(func(ctx context.Context, a *types.Action) types.ActionResult {
		// Simulate work that runs past the action's deadline.
		time.Sleep(2 * settings.ActionProcessTimeout)
		// Production pattern: timeout check before changing state.
		if err := ctx.Err(); err != nil {
			return types.ActionResult{ID: a.Data.ID, Status: 0, Log: err.Error()}
		}
		return types.ActionResult{ID: a.Data.ID, Status: 1, Log: "committed (should-not-reach)"}
	})
	// Replace the FDC2/Prove route so r.process picks our cooperative processor.
	delete(r.routs, types.OpID{OPType: op.FDC2.Hash(), OPCommand: op.Prove.Hash()})
	r.RegisterProcessor(op.FDC2, op.Prove, cooperative)

	start := time.Now()
	result := r.processWithTimeout(timeoutTestAction(), processorutils.Main)
	elapsed := time.Since(start)

	require.Equal(t, uint8(0), result.Status)
	require.Equal(t, context.DeadlineExceeded.Error(), result.Log,
		"expected the processor's own ctx.Err() to surface, proving the guard fired before commit")
	require.Less(t, elapsed, settings.ActionProcessTimeout+settings.ActionDrainTimeout,
		"worker should have returned well before the drain window expired")
	require.GreaterOrEqual(t, elapsed, settings.ActionProcessTimeout,
		"worker should have waited at least for the action timeout to fire")
}

// TestProcessWithTimeout_NonCooperativeProcessor verifies that a processor
// which ignores ctx gets abandoned after the drain window and the worker
// returns the explicit "state may be inconsistent" error rather than wedging
// the queue forever. The goroutine intentionally leaks past test end; we wait
// briefly to let it finish so the test runner exits cleanly.
func TestProcessWithTimeout_NonCooperativeProcessor(t *testing.T) {
	shrinkActionTimeouts(t, 100*time.Millisecond, 200*time.Millisecond)

	testNode, ps, ws := testutils.Setup(t)
	r := NewPMWRouter(testNode, ws, ps, &settings.ProxyURLMutex{})

	processorSleep := settings.ActionProcessTimeout + settings.ActionDrainTimeout + 500*time.Millisecond
	done := make(chan struct{})
	nonCooperative := ProcessFunc(func(_ context.Context, a *types.Action) types.ActionResult {
		time.Sleep(processorSleep)
		close(done)
		return types.ActionResult{ID: a.Data.ID, Status: 1, Log: "should-never-surface"}
	})
	delete(r.routs, types.OpID{OPType: op.FDC2.Hash(), OPCommand: op.Prove.Hash()})
	r.RegisterProcessor(op.FDC2, op.Prove, nonCooperative)

	start := time.Now()
	result := r.processWithTimeout(timeoutTestAction(), processorutils.Main)
	elapsed := time.Since(start)

	require.Equal(t, uint8(0), result.Status)
	require.Contains(t, result.Log, "failed to drain")
	require.Contains(t, result.Log, "TEE state may be inconsistent")
	require.Less(t, elapsed, processorSleep,
		"worker should have abandoned the goroutine instead of waiting for it to finish")
	require.GreaterOrEqual(t, elapsed, settings.ActionProcessTimeout+settings.ActionDrainTimeout,
		"worker should have waited at least through both windows")

	// Let the abandoned goroutine finish so the test runner has nothing in flight.
	<-done
}
