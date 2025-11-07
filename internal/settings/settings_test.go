package settings_test

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/stretchr/testify/require"
)

// Examples.
const (
	proxyURL  = "http://proxy.com"
	proxyURL2 = "http://newproxy.com"
	h         = "0x7f3c9a1d4b82e6f0c5d9a7b1e2f4c8d6a1b3e9f7c0d4a8b2e6f1c3d9a7b5e2f8"
	h2        = "0xa4d7c2f9e1b0835d6c7a9f4e2d1b6a3c9e8f7d5b4c2a1908e7f6d4c3b2a1e0f9"
)

var (
	a  = common.HexToAddress(h)
	a2 = common.HexToAddress(h2)
)

type request struct {
	name     string
	body     string
	expected int
}

// setup returns pointers to a test config server and node.
func setup() (*settings.ProxyConfigureServer, *node.Node) {
	n, _ := node.Initialize(node.ZeroState{})
	server := settings.NewConfigServer(3000, n)
	go server.Serve() //nolint:errcheck
	time.Sleep(100 * time.Millisecond)
	return server, n
}

// postAndCheckCode posts a request to the test config server and checks the responded status code.
func postAndCheckCode(t *testing.T, endpoint string, requestBody string, expectedStatusCode int) {
	resp, err := http.Post("http://localhost:3000"+endpoint, "application/json", bytes.NewBufferString(requestBody))
	require.NoError(t, err)

	require.Equal(t, expectedStatusCode, resp.StatusCode)

	require.NoError(t, resp.Body.Close())
}

// checkProxyURL safely checks a config server's proxy URL.
func checkProxyURL(t *testing.T, server *settings.ProxyConfigureServer, expectedProxyURL string) {
	server.ProxyURL.RLock()
	defer server.ProxyURL.RUnlock()
	require.Equal(t, expectedProxyURL, server.ProxyURL.URL)
}

// TestPROXY_ENV checks that a config server correctly uses the PROXY_ENV environment variable.
func TestPROXYENV(t *testing.T) {
	t.Run("with unset PROXY_ENV", func(t *testing.T) {
		require.NoError(t, os.Unsetenv(settings.ProxyURLEnvVar))

		server, _ := setup()
		defer server.Close(context.Background()) //nolint:errcheck

		checkProxyURL(t, server, "")
	})

	t.Run("with set PROXY_ENV", func(t *testing.T) {
		require.NoError(t, os.Setenv(settings.ProxyURLEnvVar, proxyURL))
		defer os.Unsetenv(settings.ProxyURLEnvVar) //nolint:errcheck

		server, _ := setup()
		defer server.Close(context.Background()) //nolint:errcheck

		checkProxyURL(t, server, proxyURL)
	})
}

// TestEndpointURLSet tests a config server's /proxy endpoint.
func TestEndpointProxy(t *testing.T) {
	server, _ := setup()
	defer server.Close(context.Background()) //nolint:errcheck

	t.Run("happy path", func(t *testing.T) {
		postAndCheckCode(t, settings.SetProxyURLEndpoint, `{"url": "`+proxyURL+`"}`, http.StatusOK)
		checkProxyURL(t, server, proxyURL)
	})

	t.Run("happy path again", func(t *testing.T) {
		postAndCheckCode(t, settings.SetProxyURLEndpoint, `{"url": "`+proxyURL2+`"}`, http.StatusOK)
		checkProxyURL(t, server, proxyURL2)
	})

	requests := []request{
		{
			name:     "invalid JSON",
			body:     "{invalid json}",
			expected: http.StatusBadRequest,
		},
		{
			name:     "unexpected field in JSON",
			body:     `{"url": "` + proxyURL + `", "un": "expected"}`,
			expected: http.StatusBadRequest,
		},
		{
			name:     "missing url field in JSON",
			body:     "{}",
			expected: http.StatusBadRequest,
		},
		{
			name:     `invalid URL in "url" field`,
			body:     `{"url": "http://invalid url"}`,
			expected: http.StatusBadRequest,
		},
	}

	for _, r := range requests {
		t.Run(r.name, func(t *testing.T) {
			postAndCheckCode(t, settings.SetProxyURLEndpoint, r.body, r.expected)

			checkProxyURL(t, server, proxyURL2)
		})
	}
}

// TestEndpointExtensionID tests a config server's /extension-id endpoint.
func TestEndpointExtensionID(t *testing.T) {
	server, n := setup()
	defer server.Close(context.Background()) //nolint:errcheck

	// TODO: This should be bad request. Instead it sets id to zero hash (which also breaks the following tests).
	// t.Run("missing extensionId field in JSON", func(t *testing.T) {
	// 	postAndCheckCode(t, settings.SetExtensionIDEndpoint, `{}`, http.StatusBadRequest)
	// })

	t.Run("happy path", func(t *testing.T) {
		postAndCheckCode(t, settings.SetExtensionIDEndpoint, `{"extensionid": "`+h+`"}`, http.StatusOK)
		require.Equal(t, common.HexToHash(h), n.Info().ExtensionID)
	})

	requests := []request{
		{
			name:     "invalid JSON",
			body:     "{invalid json}",
			expected: http.StatusBadRequest,
		},
		{
			name:     "unexpected field in JSON",
			body:     `{"extensionId": "` + h + `", "un": "expected"}`,
			expected: http.StatusBadRequest,
		},
		{
			name:     `invalid extension id`,
			body:     `{"extensionId": "0xnothash"}`,
			expected: http.StatusBadRequest,
		},
		{
			name:     "setting an already set extension id", // It was already set by happy path.
			body:     `{"extensionId": "` + h2 + `"}`,
			expected: http.StatusForbidden,
		},
	}

	for _, r := range requests {
		t.Run(r.name, func(t *testing.T) {
			postAndCheckCode(t, settings.SetExtensionIDEndpoint, r.body, r.expected)
		})
	}
}

// TestEndpointInitialOwner tests a config server's /initial-owner endpoint.
func TestEndpointInitialOwner(t *testing.T) {
	server, n := setup()
	defer server.Close(context.Background()) //nolint:errcheck

	t.Run("missing owner field in JSON", func(t *testing.T) {
		postAndCheckCode(t, settings.SetInitialOwnerEndpoint, `{}`, http.StatusForbidden)
	})

	t.Run("happy path", func(t *testing.T) {
		postAndCheckCode(t, settings.SetInitialOwnerEndpoint, `{"owner": "`+a.String()+`"}`, http.StatusOK)
		require.Equal(t, a, n.Info().InitialOwner)
	})

	requests := []request{
		{
			name:     "invalid JSON",
			body:     "{invalid json}",
			expected: http.StatusBadRequest,
		},
		{
			name:     "unexpected field in JSON",
			body:     `{"owner": "` + a.String() + `", "un": "expected"}`,
			expected: http.StatusBadRequest,
		},
		{
			name:     `invalid address`,
			body:     `{"owner": "0xnotaddress"}`,
			expected: http.StatusBadRequest,
		},
		{
			name:     `zero address`,
			body:     `{"owner": "` + common.Address{}.String() + `"}`,
			expected: http.StatusForbidden,
		},
		{
			name:     "setting an already set initial owner", // It was already set by happy path.
			body:     `{"owner": "` + a2.String() + `"}`,
			expected: http.StatusForbidden,
		},
	}

	for _, r := range requests {
		t.Run(r.name, func(t *testing.T) {
			postAndCheckCode(t, settings.SetInitialOwnerEndpoint, r.body, r.expected)
		})
	}
}
