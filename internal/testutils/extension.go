package testutils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/flare-foundation/tee-node/pkg/processorutils"
	"github.com/flare-foundation/tee-node/pkg/types"
)

type DummyExtensionServer struct {
	server   *http.Server
	port     int
	signPort int
	version  string
}

// NewDummyExtensionServer spins up a mock signing server that exercises the
// TEE-node interface for local development.
func NewDummyExtensionServer(port, signPort int) *DummyExtensionServer {
	addr := fmt.Sprintf(":%d", port)

	server := &http.Server{
		Addr: addr,
	}

	e := DummyExtensionServer{
		server:   server,
		port:     port,
		signPort: signPort,
		version:  "0.0.0-test",
	}

	e.registerRoutes()

	return &e
}

// registerRoutes registers the /action endpoint.
func (d *DummyExtensionServer) registerRoutes() {
	mux := http.NewServeMux()
	d.server.Handler = mux

	// Dummy action endpoint
	mux.HandleFunc("POST /action", d.actionHandler)
}

// actionHandler handles /action requests.
func (d *DummyExtensionServer) actionHandler(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var action types.Action

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&action); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate action data
	if err := d.validateAction(&action); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Process the action (dummy implementation)
	// In a real extension, this would contain the actual business logic
	if err := d.processAction(&action); err != nil {
		http.Error(w, fmt.Sprintf("Failed to process action: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	oi, err := opInfo(&action)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result := types.ActionResult{
		ID:                     action.Data.ID,
		SubmissionTag:          action.Data.SubmissionTag,
		Status:                 2,
		Log:                    "action in processing",
		OPType:                 oi.OPType,
		OPCommand:              oi.OPCommand,
		AdditionalResultStatus: hexutil.Bytes{},
		Version:                d.version,
		Data:                   hexutil.Bytes{},
	}

	b, err := json.Marshal(result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err = w.Write(b)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// validateAction checks that action fields are not zero.
func (d *DummyExtensionServer) validateAction(action *types.Action) error {
	if action.Data.ID == [32]byte{} {
		return fmt.Errorf("action ID is required")
	}

	if action.Data.Type == "" {
		return fmt.Errorf("action type is required")
	}

	if action.Data.SubmissionTag == "" {
		return fmt.Errorf("submission tag is required")
	}

	if len(action.Data.Message) == 0 {
		return fmt.Errorf("action message is required")
	}

	return nil
}

// processAction mocks processing an action.
func (d *DummyExtensionServer) processAction(action *types.Action) error {
	// Dummy processing logic
	// In a real extension, this would:
	// 1. Parse the action data
	// 2. Execute the appropriate business logic
	// 3. Store results
	// 4. Handle any errors

	logger.Infof("Processing action: ID=%s, Type=%s, SubmissionTag=%s",
		action.Data.ID.Hex(), action.Data.Type, action.Data.SubmissionTag)

	// Simulate some processing time or potential errors
	// For demo purposes, we'll just log the action details

	switch action.Data.Type {
	case types.Instruction:
		logger.Infof("Processing instruction action")
		go d.mockPostActionResult(action)
	case types.Direct:
		logger.Infof("Processing direct action")
		go d.mockPostActionResult(action)
	default:
		return fmt.Errorf("unknown action type: %s", action.Data.Type)
	}

	return nil
}

// mockPostActionResult sleeps and posts a mock action result to localhost:teePort/result.
func (d *DummyExtensionServer) mockPostActionResult(action *types.Action) {
	time.Sleep(50 * time.Millisecond)
	url := fmt.Sprintf("http://localhost:%d/result", d.signPort)

	result := d.mockActionResult(action)

	encRes, err := json.Marshal(result)
	if err != nil {
		logger.Errorf("Failed to marshal result: %s", err.Error())
	}

	res, err := http.Post(url, "application/json", bytes.NewReader(encRes))
	if err != nil {
		logger.Errorf("Failed to send post request: %s", err.Error())
	}

	defer res.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(res.Body)
	if err != nil {
		logger.Errorf("Failed to read response body: %s", err.Error())
	}
	if res.StatusCode != http.StatusOK {
		logger.Errorf("unexpected status code: %d, response: %s", res.StatusCode, string(body))
	}
}

// mockActionResult sleeps and returns a mock action result.
func (d *DummyExtensionServer) mockActionResult(action *types.Action) types.ActionResult {
	time.Sleep(50 * time.Millisecond)

	oi, err := opInfo(action)
	if err != nil {
		return processorutils.Invalid(action, err)
	}

	return types.ActionResult{
		ID:            action.Data.ID,
		SubmissionTag: action.Data.SubmissionTag,
		Status:        1,
		Log:           fmt.Sprintf("Action (type: %s) processed successfully", action.Data.Type),
		OPType:        oi.OPType,
		OPCommand:     oi.OPCommand,
		Version:       d.version,
		Data:          action.Data.Message,
	}
}

// Serve starts the dummy extension HTTP server.
func (d *DummyExtensionServer) Serve() error {
	logger.Infof("Starting dummy extension server on port %d", d.port)
	return d.server.ListenAndServe()
}

// Close shuts down the dummy extension server.
func (d *DummyExtensionServer) Close() error {
	logger.Infof("Shutting down dummy extension server")
	return d.server.Close()
}

type ops struct {
	OPType    common.Hash `json:"opType"`
	OPCommand common.Hash `json:"opCommand"`
}

// opInfo extracts [ops] from the action.
func opInfo(a *types.Action) (ops, error) {
	var ops ops
	err := json.Unmarshal(a.Data.Message, &ops)
	return ops, err
}
