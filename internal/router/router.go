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

func (p ProcessFunc) Process(a *types.Action) types.ActionResult {
	return p(a)
}

// Router assigns an action to a designated processor based on its opType and opCommand.
//
// Actions that do not have a designated processor are routed to defaultDirect or defaultInstruction based on action type.
type Router struct {
	routs map[rID]Processor

	defaultDirect      Processor
	defaultInstruction Processor

	proxyUrl *settings.ProxyURLMutex
}

func New(proxyUrl *settings.ProxyURLMutex) Router {
	return Router{proxyUrl: proxyUrl}
}

func (r Router) Run(signer node.Signer) {
	go r.ServeQueue(processorutils.Main, signer)
	r.ServeQueue(processorutils.Direct, signer)
}

// ServeQueue starts an endless loop that fetches actions from proxy's queue, processes them, and posts the response to the proxy.
func (r *Router) ServeQueue(id processorutils.QueueID, signer node.Signer) {
	for {
		var action *types.Action
		var result types.ActionResult
		var response *types.ActionResponse
		var err error

		r.proxyUrl.RLock()
		proxyURL := r.proxyUrl.URL
		r.proxyUrl.RUnlock()
		if proxyURL == "" {
			goto sleep
		}

		action, err = queue.FetchAction(fmt.Sprintf("%s/queue/%s", proxyURL, id))
		if err != nil {
			// logger.Errorf("error getting action: %v", err)
			goto sleep
		}
		if action == nil || action.Data.ID == [32]byte{} {
			goto sleep
		}

		result = r.process(action)

		response, _ = SignResult(&result, signer)

		err = queue.PostActionResponse(proxyURL+"/result", response)
		if err != nil {
			logger.Errorf("error posting result: %v", err)
		}
		continue

	sleep:
		time.Sleep(settings.QueuedActionsSleepTime)
	}
}

// RegisterProcessor registers processor for the pair of opType and opCommand.
//
// Only one processor per pair is allowed.
func (r *Router) RegisterProcessor(opType op.Type, opCommand op.Command, processor Processor) {
	routID := rID{
		OPType:    opType.Hash(),
		OPCommand: opCommand.Hash(),
	}

	if r.routs == nil {
		r.routs = make(map[rID]Processor)
	}

	if _, exists := r.routs[routID]; exists {
		panic(fmt.Sprintf("duplicated processor for %v, %v", opType, opCommand))
	}

	r.routs[routID] = processor
}

func (r *Router) RegisterProcessFunc(opType op.Type, opCommand op.Command, processFunc ProcessFunc) {
	r.RegisterProcessor(opType, opCommand, processFunc)
}

func (r *Router) RegisterDirectProcessor(opType op.Type, opCommand op.Command, processor direct.Processor) {
	r.RegisterProcessor(opType, opCommand, processor)
}

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

func (r *Router) process(a *types.Action) types.ActionResult {
	err := processorutils.CheckAndAdapt(a)
	if err != nil {
		return processorutils.Invalid(a, err)
	}

	id, err := routID(a)
	if err != nil {
		return processorutils.Invalid(a, err)
	}

	p, exists := r.routs[id]
	if exists {
		return p.Process(a)
	}

	switch a.Data.Type {
	case types.Direct:
		if r.defaultDirect != nil {
			return r.defaultDirect.Process(a)
		}
	case types.Instruction:
		if r.defaultInstruction != nil {
			return r.defaultInstruction.Process(a)
		}
	}

	return processorutils.Invalid(a, fmt.Errorf("processor for %s not registered", id.String()))
}
