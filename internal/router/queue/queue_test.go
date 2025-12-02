package queue_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/flare-foundation/tee-node/internal/router/queue"
	"github.com/flare-foundation/tee-node/pkg/types"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"
)

// queueTestSetup provides common test setup for queue tests
type queueTestSetup struct {
	server *httptest.Server
	url    string
}

// setupQueueTest creates a test HTTP server for queue testing
func setupQueueTest() *queueTestSetup {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Default handler - can be overridden in individual tests
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}))

	return &queueTestSetup{
		server: server,
		url:    server.URL,
	}
}

// teardownQueueTest cleans up the test server
func (s *queueTestSetup) teardownQueueTest() {
	s.server.Close()
}

// createMockAction creates a valid Action for testing
func createMockAction() *types.Action {
	return &types.Action{
		Data: types.ActionData{
			ID:            common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
			Type:          types.Instruction,
			SubmissionTag: types.Threshold,
			Message:       hexutil.Bytes{0x01, 0x02, 0x03},
		},
		AdditionalVariableMessages: []hexutil.Bytes{{0x04, 0x05}},
		Timestamps:                 []uint64{1234567890},
		AdditionalActionData:       hexutil.Bytes{0x06, 0x07},
		Signatures:                 []hexutil.Bytes{{0x08, 0x09}},
	}
}

// createMockActionResponse creates a valid ActionResponse for testing
func createMockActionResponse() *types.ActionResponse {
	return &types.ActionResponse{
		Result: types.ActionResult{
			ID:                     common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
			SubmissionTag:          types.Submit,
			Status:                 1,
			Log:                    "test log",
			OPType:                 common.HexToHash("0x01"),
			OPCommand:              common.HexToHash("0x02"),
			AdditionalResultStatus: hexutil.Bytes{0x03},
			Version:                "1.0.0",
			Data:                   hexutil.Bytes{0x04, 0x05},
		},
		Signature:      hexutil.Bytes{0x06, 0x07},
		ProxySignature: hexutil.Bytes{0x08, 0x09},
	}
}

// ============================ FetchAction Tests ============================

// TestFetchAction_Success tests successful action fetching
func TestFetchAction_Success(t *testing.T) {
	setup := setupQueueTest()
	defer setup.teardownQueueTest()

	mockAction := createMockAction()
	actionJSON, err := json.Marshal(mockAction)
	require.NoError(t, err)

	// Override server handler to return mock action
	setup.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(actionJSON)
	})

	action, err := queue.FetchAction(setup.url)
	require.NoError(t, err)
	require.NotNil(t, action)
	require.Equal(t, mockAction.Data.ID, action.Data.ID)
	require.Equal(t, mockAction.Data.Type, action.Data.Type)
	require.Equal(t, mockAction.Data.SubmissionTag, action.Data.SubmissionTag)
}

// TestFetchAction_HTTPError tests HTTP connection errors
func TestFetchAction_HTTPError(t *testing.T) {
	// Use invalid URL to trigger connection error
	_, err := queue.FetchAction("http://invalid-url-that-does-not-exist:9999")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no such host")
}

// TestFetchAction_NonOKStatus tests non-200 HTTP status codes
func TestFetchAction_NonOKStatus(t *testing.T) {
	setup := setupQueueTest()
	defer setup.teardownQueueTest()

	// Override server handler to return error status
	setup.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal Server Error"))
	})

	_, err := queue.FetchAction(setup.url)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected status code: 500")
	require.Contains(t, err.Error(), "Internal Server Error")
}

// TestFetchAction_InvalidJSON tests invalid JSON response
func TestFetchAction_InvalidJSON(t *testing.T) {
	setup := setupQueueTest()
	defer setup.teardownQueueTest()

	// Override server handler to return invalid JSON
	setup.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid json response"))
	})

	_, err := queue.FetchAction(setup.url)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid character")
}

// TestFetchAction_EmptyResponse tests empty response body
func TestFetchAction_EmptyResponse(t *testing.T) {
	setup := setupQueueTest()
	defer setup.teardownQueueTest()

	// Override server handler to return empty body
	setup.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(""))
	})

	_, err := queue.FetchAction(setup.url)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected end of JSON input")
}

// TestFetchAction_Timeout tests HTTP timeout behavior
func TestFetchAction_Timeout(t *testing.T) {
	setup := setupQueueTest()
	defer setup.teardownQueueTest()

	// Override server handler to delay response beyond timeout
	setup.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second) // Longer than ProxyTimeout
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	})

	_, err := queue.FetchAction(setup.url)
	require.Error(t, err)
	require.Contains(t, err.Error(), "context deadline exceeded")
}

// ============================ PostActionResponse Tests ============================

// TestPostActionResponse_Success tests successful response posting
func TestPostActionResponse_Success(t *testing.T) {
	setup := setupQueueTest()
	defer setup.teardownQueueTest()

	mockResponse := createMockActionResponse()
	var receivedResponse *types.ActionResponse

	// Override server handler to capture and verify the posted response
	setup.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var postedResponse types.ActionResponse
		err = json.Unmarshal(body, &postedResponse)
		require.NoError(t, err)

		receivedResponse = &postedResponse
		w.WriteHeader(http.StatusOK)
	})

	err := queue.PostActionResponse(setup.url, mockResponse)
	require.NoError(t, err)
	require.NotNil(t, receivedResponse)
	require.Equal(t, mockResponse.Result.ID, receivedResponse.Result.ID)
	require.Equal(t, mockResponse.Result.Status, receivedResponse.Result.Status)
}

// TestPostActionResponse_HTTPError tests HTTP connection errors
func TestPostActionResponse_HTTPError(t *testing.T) {
	mockResponse := createMockActionResponse()

	// Use invalid URL to trigger connection error
	err := queue.PostActionResponse("http://invalid-url-that-does-not-exist:9999", mockResponse)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no such host")
}

// TestPostActionResponse_NonOKStatus tests non-200 HTTP status codes
func TestPostActionResponse_NonOKStatus(t *testing.T) {
	setup := setupQueueTest()
	defer setup.teardownQueueTest()

	mockResponse := createMockActionResponse()

	// Override server handler to return error status
	setup.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Bad Request"))
	})

	err := queue.PostActionResponse(setup.url, mockResponse)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected status code: 400")
	require.Contains(t, err.Error(), "Bad Request")
}

// TestPostActionResponse_Timeout tests HTTP timeout behavior
func TestPostActionResponse_Timeout(t *testing.T) {
	setup := setupQueueTest()
	defer setup.teardownQueueTest()

	mockResponse := createMockActionResponse()

	// Override server handler to delay response beyond timeout
	setup.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second) // Longer than ProxyTimeout
		w.WriteHeader(http.StatusOK)
	})

	err := queue.PostActionResponse(setup.url, mockResponse)
	require.Error(t, err)
	require.Contains(t, err.Error(), "context deadline exceeded")
}

// ============================ Integration Tests ============================

// TestQueueIntegration_FetchAndPost tests the complete flow of fetching and posting
func TestQueueIntegration_FetchAndPost(t *testing.T) {
	setup := setupQueueTest()
	defer setup.teardownQueueTest()

	mockAction := createMockAction()
	actionJSON, err := json.Marshal(mockAction)
	require.NoError(t, err)

	var postedResponse *types.ActionResponse

	// Set up server to handle both fetch and post
	setup.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			if r.Header.Get("Content-Type") == "application/json" {
				// This is a POST request with JSON body (PostActionResponse)
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)

				var response types.ActionResponse
				err = json.Unmarshal(body, &response)
				require.NoError(t, err)

				postedResponse = &response
			} else {
				// This is a POST request without body (FetchAction)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(actionJSON)
			}
		}
		w.WriteHeader(http.StatusOK)
	})

	// Test fetch action
	action, err := queue.FetchAction(setup.url)
	require.NoError(t, err)
	require.NotNil(t, action)

	require.Equal(t, mockAction.Data.ID, action.Data.ID)
	require.Equal(t, mockAction.Data.Type, action.Data.Type)
	require.Equal(t, mockAction.Data.SubmissionTag, action.Data.SubmissionTag)

	// Test post response
	mockResponse := createMockActionResponse()
	err = queue.PostActionResponse(setup.url, mockResponse)
	require.NoError(t, err)
	require.NotNil(t, postedResponse)

	require.Equal(t, mockResponse.Result.ID, postedResponse.Result.ID)
	require.Equal(t, mockResponse.Result.Status, postedResponse.Result.Status)
	require.Equal(t, mockResponse.Signature, postedResponse.Signature)
	require.Equal(t, mockResponse.ProxySignature, postedResponse.ProxySignature)
}

// TestQueueIntegration_ServerUnavailable tests behavior when server is unavailable
func TestQueueIntegration_ServerUnavailable(t *testing.T) {
	setup := setupQueueTest()
	setup.teardownQueueTest() // Close server immediately

	// Test fetch action with closed server
	_, err := queue.FetchAction(setup.url)
	require.Error(t, err)
	require.Contains(t, err.Error(), "connection refused")

	// Test post response with closed server
	mockResponse := createMockActionResponse()
	err = queue.PostActionResponse(setup.url, mockResponse)
	require.Error(t, err)
	require.Contains(t, err.Error(), "connection refused")
}
