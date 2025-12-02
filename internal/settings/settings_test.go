package settings_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/stretchr/testify/require"
)

const defaultProxyURL = ""

var (
	defaultExtensionID  = settings.DefaultExtensionID
	defaultInitialOwner = common.Address{}
)

type request struct {
	name     string
	body     string
	expected int
}

// Examples.
const (
	proxyURL  = "http://proxy.com"
	proxyURL2 = "http://newproxy.com"
	h         = "0x7f3c9a1d4b82e6f0c5d9a7b1e2f4c8d6a1b3e9f7c0d4a8b2e6f1c3d9a7b5e2f8"
	h2        = "0xa4d7c2f9e1b0835d6c7a9f4e2d1b6a3c9e8f7d5b4c2a1908e7f6d4c3b2a1e0f9"
)

// Examples.
var (
	a  = common.HexToAddress(h)
	a2 = common.HexToAddress(h2)
)

// setup returns pointers to a test config server and node.
func setup() (*settings.ConfigServer, *node.Node) {
	n, _ := node.Initialize(node.ZeroState{})
	server := settings.NewConfigServer(3000, n)
	go server.Serve() //nolint:errcheck
	time.Sleep(100 * time.Millisecond)
	return server, n
}

// postAndCheckCode posts a request to the test config server and checks the responded status code.
func postAndCheckCode(t *testing.T, endpoint string, requestBody string, expectedStatusCode int) {
	t.Helper()

	resp, err := http.Post("http://localhost:3000"+endpoint, "application/json", bytes.NewBufferString(requestBody))
	require.NoError(t, err)

	require.Equal(t, expectedStatusCode, resp.StatusCode)

	require.NoError(t, resp.Body.Close())
}

// checkProxyURL safely checks a config server's proxy URL.
func checkProxyURL(t *testing.T, server *settings.ConfigServer, expectedProxyURL string) {
	t.Helper()

	server.ProxyURL.RLock()
	defer server.ProxyURL.RUnlock()

	require.Equal(t, expectedProxyURL, server.ProxyURL.URL)
}

// checkExtensionID checks that a node's extension id is the given hash.
func checkExtensionID[T string | common.Hash](t *testing.T, n *node.Node, hash T) {
	t.Helper()

	ID := n.Info().ExtensionID

	switch h := any(hash).(type) {
	case string:
		require.Equal(t, common.HexToHash(h), ID)
	case common.Hash:
		require.Equal(t, h, ID)
	}
}

// checkInitialOwner checks that the given address is the node's initial owner.
func checkInitialOwner(t *testing.T, n *node.Node, a common.Address) {
	t.Helper()

	require.Equal(t, a, n.Info().InitialOwner)
}

// setEnvVars sets test environment variables.
func setEnvVars(t *testing.T) {
	t.Helper()

	require.NoError(t, os.Setenv(settings.ProxyURLEnvVar, proxyURL))
	require.NoError(t, os.Setenv(settings.ExtensionIDEnvVar, h))
	require.NoError(t, os.Setenv(settings.InitialOwnerEnvVar, hex.EncodeToString(a[:])))
}

// unsetEnvVars unsets test environment variables.
func unsetEnvVars(t *testing.T) {
	t.Helper()

	for _, v := range [3]string{settings.ProxyURLEnvVar, settings.ExtensionIDEnvVar, settings.InitialOwnerEnvVar} {
		require.NoError(t, os.Unsetenv(v))
	}
}

// TestDefaults checks that a config server correctly uses environment variables,
// and has the right default when such a variable is unset.
func TestDefaults(t *testing.T) {
	t.Run("with unset environment variables", func(t *testing.T) {
		unsetEnvVars(t)

		server, n := setup()
		defer server.Close(context.Background()) //nolint:errcheck

		checkProxyURL(t, server, defaultProxyURL)
		checkExtensionID(t, n, defaultExtensionID)
		checkInitialOwner(t, n, defaultInitialOwner)
	})

	t.Run("with set environment variables", func(t *testing.T) {
		setEnvVars(t)
		defer unsetEnvVars(t)

		server, n := setup()
		defer server.Close(context.Background()) //nolint:errcheck

		checkProxyURL(t, server, proxyURL)
		checkExtensionID(t, n, h)
		checkInitialOwner(t, n, a)
	})
}

// TestEndpointURLSet tests a config server's /proxy endpoint.
func TestEndpointProxy(t *testing.T) {
	requests := []request{
		{
			name:     "invalid JSON",
			body:     "{invalid json}",
			expected: http.StatusBadRequest,
		},
		{
			name:     "missing url field in JSON",
			body:     "{}",
			expected: http.StatusBadRequest,
		},
		{
			name:     "unexpected field in JSON",
			body:     `{"url": "` + proxyURL + `", "un": "expected"}`,
			expected: http.StatusBadRequest,
		},
		{
			name:     `invalid URL in "url" field`,
			body:     `{"url": "http://invalid url"}`,
			expected: http.StatusBadRequest,
		},
	}

	for _, setProxyURL := range [2]bool{false, true} {
		func() {
			server, _ := setup()
			defer server.Close(context.Background()) //nolint:errcheck

			if setProxyURL {
				t.Run("set proxy URL", func(t *testing.T) {
					postAndCheckCode(t, settings.SetProxyURLEndpoint, `{"url": "`+proxyURL+`"}`, http.StatusOK)
					checkProxyURL(t, server, proxyURL)
				})

				for _, r := range requests {
					t.Run(r.name, func(t *testing.T) {
						postAndCheckCode(t, settings.SetProxyURLEndpoint, r.body, r.expected)
						checkProxyURL(t, server, proxyURL)
					})
				}

				t.Run("set proxy URL again", func(t *testing.T) {
					postAndCheckCode(t, settings.SetProxyURLEndpoint, `{"url": "`+proxyURL2+`"}`, http.StatusOK)
					checkProxyURL(t, server, proxyURL2)
				})
			} else {
				for _, r := range requests {
					t.Run(r.name, func(t *testing.T) {
						postAndCheckCode(t, settings.SetProxyURLEndpoint, r.body, r.expected)
						checkProxyURL(t, server, defaultProxyURL)
					})
				}

				t.Run("set proxy URL 2", func(t *testing.T) {
					postAndCheckCode(t, settings.SetProxyURLEndpoint, `{"url": "`+proxyURL+`"}`, http.StatusOK)
					checkProxyURL(t, server, proxyURL)
				})
			}
		}()
	}
}

// TestEndpointExtensionID tests a config server's /extension-id endpoint.
func TestEndpointExtensionID(t *testing.T) {
	requests := []request{
		{
			name:     "invalid JSON",
			body:     "{invalid json}",
			expected: http.StatusBadRequest,
		},
		{
			name:     "missing extensionId field in JSON",
			body:     "{}",
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
	}

	for _, SetExtensionID := range [2]bool{false, true} {
		func() {
			server, n := setup()
			defer server.Close(context.Background()) //nolint:errcheck

			if SetExtensionID {
				t.Run("set extension ID", func(t *testing.T) {
					postAndCheckCode(t, settings.SetExtensionIDEndpoint, `{"extensionId": "`+h+`"}`, http.StatusOK)
					checkExtensionID(t, n, h)
				})

				requests = append(requests, request{
					name:     "set extension ID again",
					body:     `{"extensionId": "` + h2 + `"}`,
					expected: http.StatusForbidden,
				})

				for _, r := range requests {
					t.Run(r.name, func(t *testing.T) {
						postAndCheckCode(t, settings.SetExtensionIDEndpoint, r.body, r.expected)
						checkExtensionID(t, n, h)
					})
				}
			} else {
				for _, r := range requests {
					t.Run(r.name, func(t *testing.T) {
						postAndCheckCode(t, settings.SetExtensionIDEndpoint, r.body, r.expected)
						checkExtensionID(t, n, defaultExtensionID)
					})
				}

				t.Run("set extension ID 2", func(t *testing.T) {
					postAndCheckCode(t, settings.SetExtensionIDEndpoint, `{"extensionId": "`+h+`"}`, http.StatusOK)
					checkExtensionID(t, n, h)
				})
			}
		}()
	}
}

// TestEndpointInitialOwner tests a config server's /initial-owner endpoint.
func TestEndpointInitialOwner(t *testing.T) {
	requests := []request{
		{
			name:     "invalid JSON",
			body:     "{invalid json}",
			expected: http.StatusBadRequest,
		},
		{
			name:     `missing owner field in JSON`,
			body:     `{}`,
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
	}

	for _, setInitialOwner := range [2]bool{false, true} {
		func() {
			server, n := setup()
			defer server.Close(context.Background()) //nolint:errcheck

			if setInitialOwner {
				t.Run("set initial owner", func(t *testing.T) {
					postAndCheckCode(t, settings.SetInitialOwnerEndpoint, `{"owner": "`+a.String()+`"}`, http.StatusOK)
					checkInitialOwner(t, n, a)
				})

				requests = append(requests, request{
					name:     "set initial owner again",
					body:     `{"owner": "` + a2.String() + `"}`,
					expected: http.StatusForbidden,
				})

				for _, r := range requests {
					t.Run(r.name, func(t *testing.T) {
						postAndCheckCode(t, settings.SetInitialOwnerEndpoint, r.body, r.expected)
						checkInitialOwner(t, n, a)
					})
				}
			} else {
				for _, r := range requests {
					t.Run(r.name, func(t *testing.T) {
						postAndCheckCode(t, settings.SetInitialOwnerEndpoint, r.body, r.expected)
						checkInitialOwner(t, n, defaultInitialOwner)
					})
				}

				t.Run("set initial owner 2", func(t *testing.T) {
					postAndCheckCode(t, settings.SetInitialOwnerEndpoint, `{"owner": "`+a.String()+`"}`, http.StatusOK)
					checkInitialOwner(t, n, a)
				})
			}
		}()
	}
}
