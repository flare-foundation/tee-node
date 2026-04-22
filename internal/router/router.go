// Package router implements action routing to the designated processors.
package router

import (
	"fmt"
	"time"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/tee-node/internal/processors/direct"
	"github.com/flare-foundation/tee-node/internal/processors/instructions"
	"github.com/flare-foundation/tee-node/internal/router/queue"

	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/processorutils"
	"github.com/flare-foundation/tee-node/pkg/types"
)

type Processor interface {
	Process(*types.Action) types.ActionResult
}

type ProcessFunc func(*types.Action) types.ActionResult

// Process calls the wrapped function to produce an action result.
func (p ProcessFunc) Process(a *types.Action) types.ActionResult {
	return p(a)
}

// Router assigns an action to a designated processor based on its opType and opCommand.
//
// Actions that do not have a designated processor are routed to defaultDirect or defaultInstruction based on action type.
type Router struct {
	routs map[types.OpID]Processor

	defaultDirect      Processor
	defaultInstruction Processor

	proxyURL *settings.ProxyURLMutex
}

// New creates a router associated with the provided proxy URL mutex.
func New(proxyURL *settings.ProxyURLMutex) Router {
	return Router{proxyURL: proxyURL}
}

// Run spawns workers processing queues for both the instructions and
// direct instructions.
func (r Router) Run(signer node.Signer) {
	go r.ServeQueue(processorutils.Main, signer)
	go r.ServeQueue(processorutils.Direct, signer)
	r.ServeQueue(processorutils.Backup, signer)
}

// ServeQueue starts an endless loop that fetches actions from proxy's queue,
// processes them, and posts the response to the proxy.
func (r *Router) ServeQueue(id processorutils.QueueID, signer node.Signer) {
	logger.Infof("%s queue: processing started", id)
	for {
		sleep := r.serveQueueIteration(id, signer)
		if sleep {
			time.Sleep(settings.QueuedActionsSleepTime)
		}
	}
}

// serveQueueIteration executes a single iteration of the queue processing loop.
// It is separated from ServeQueue to enable panic recovery via defer.
func (r *Router) serveQueueIteration(id processorutils.QueueID, signer node.Signer) bool {
	var action *types.Action

	defer func() {
		if rec := recover(); rec != nil {
			logger.Errorf("%s queue: recovered from panic: %v", id, rec)
			result := r.errorResult(action, fmt.Sprintf("internal error: panic: %v", rec))
			r.signAndPost(id, &result, signer)
		}
	}()

	r.proxyURL.RLock()
	proxyURL := r.proxyURL.URL
	r.proxyURL.RUnlock()
	if proxyURL == "" {
		return true
	}

	var err error
	action, err = queue.FetchAction(fmt.Sprintf("%s/queue/%s", proxyURL, id))
	if err != nil {
		logger.Errorf("%s queue: error getting action: %v", id, err)
		result := r.errorResult(action, fmt.Sprintf("error fetching action: %v", err))
		r.signAndPost(id, &result, signer)
		return true
	}
	if action == nil || action.Data.ID == [32]byte{} {
		return true
	}
	logger.Infof("%s queue: fetched an action: id %v, type %v, submission tag %v", id, action.Data.ID, action.Data.Type, action.Data.SubmissionTag)

	result := r.process(action, id)
	if result.Status == 0 {
		logger.Errorf("%s queue: processing action %v error: %v", id, action.Data.ID, result.Log)
	} else {
		logger.Infof("%s queue: result of action %v obtained, status %v, log %v", id, action.Data.ID, result.Status, result.Log)
	}
	r.signAndPost(id, &result, signer)

	return false
}

// errorResult constructs a Status-0 ActionResult. If action is non-nil, its ID
// and SubmissionTag are included; otherwise the fields are left zero-valued.
func (r *Router) errorResult(action *types.Action, log string) types.ActionResult {
	result := types.ActionResult{
		Status:  0,
		Version: settings.EncodingVersion,
		Log:     log,
	}
	if action != nil {
		result.ID = action.Data.ID
		result.SubmissionTag = action.Data.SubmissionTag
	}
	return result
}

// signAndPost signs the result and posts it to the proxy.
// On failure it retries with a minimal unsigned error result.
func (r *Router) signAndPost(id processorutils.QueueID, result *types.ActionResult, signer node.Signer) {
	response, err := SignResult(result, signer)
	if err != nil {
		logger.Errorf("%s queue: error signing: %v", id, err)
	}

	r.proxyURL.RLock()
	proxyURL := r.proxyURL.URL
	r.proxyURL.RUnlock()

	err = queue.PostActionResponse(proxyURL+"/result", response)
	if err != nil {
		logger.Errorf("%s queue: error posting result: %v", id, err)

		// Retry with a minimal unsigned error-only result.
		fallback := r.errorResult(nil, fmt.Sprintf("error posting result: %v", err))
		fallbackResp := &types.ActionResponse{Result: fallback}
		if retryErr := queue.PostActionResponse(proxyURL+"/result", fallbackResp); retryErr != nil {
			logger.Errorf("%s queue: error posting fallback result: %v", id, retryErr)
		}
	}
}

// RegisterProcessor registers processor for the pair of opType and opCommand.
//
// Only one processor per pair is allowed.
func (r *Router) RegisterProcessor(opType op.Type, opCommand op.Command, processor Processor) {
	routID := types.OpID{
		OPType:    opType.Hash(),
		OPCommand: opCommand.Hash(),
	}

	if r.routs == nil {
		r.routs = make(map[types.OpID]Processor)
	}

	if _, exists := r.routs[routID]; exists {
		panic(fmt.Sprintf("duplicated processor for %v, %v", opType, opCommand))
	}

	r.routs[routID] = processor
}

// RegisterProcessFunc stores a ProcessFunc for the given op pair.
func (r *Router) RegisterProcessFunc(opType op.Type, opCommand op.Command, processFunc ProcessFunc) {
	r.RegisterProcessor(opType, opCommand, processFunc)
}

// RegisterDirectProcessor registers a direct processor for the given op pair.
func (r *Router) RegisterDirectProcessor(opType op.Type, opCommand op.Command, processor direct.Processor) {
	r.RegisterProcessor(opType, opCommand, processor)
}

// RegisterInstructionProcessor registers an instruction processor for the given
// op pair.
func (r *Router) RegisterInstructionProcessor(opType op.Type, opCommand op.Command, processor instructions.Processor) {
	r.RegisterProcessor(opType, opCommand, processor)
}

// RegisterDefaultDirect registers processor for direct actions, that do not have a designated processor.
func (r *Router) RegisterDefaultDirect(processor Processor) {
	if r.defaultDirect != nil {
		panic("default direct processor already registered")
	}

	r.defaultDirect = processor
}

// RegisterDefaultInstruction registers processor for instruction actions, that do not have a designated processor.
func (r *Router) RegisterDefaultInstruction(processor Processor) {
	if r.defaultInstruction != nil {
		panic("default instruction processor already registered")
	}

	r.defaultInstruction = processor
}

func (r *Router) process(a *types.Action, queueID processorutils.QueueID) types.ActionResult {
	err := processorutils.CheckAndAdapt(a)
	if err != nil {
		return processorutils.Invalid(a, err)
	}

	id, err := types.GetOpID(a)
	if err != nil {
		return processorutils.Invalid(a, err)
	}
	logger.Infof("%s queue: routing action with OPType, OPCommand: %v", queueID, id)

	p, exists := r.routs[id]
	if exists {
		return p.Process(a)
	}

	switch a.Data.Type {
	case types.Direct:
		if r.defaultDirect != nil {
			logger.Infof("%s queue: processing using default direct processor", queueID)
			return r.defaultDirect.Process(a)
		}
	case types.Instruction:
		if r.defaultInstruction != nil {
			logger.Infof("%s queue: processing using default instruction processor", queueID)
			return r.defaultInstruction.Process(a)
		}
	}

	return processorutils.Invalid(a, fmt.Errorf("processor for %s not registered", id.String()))
}
