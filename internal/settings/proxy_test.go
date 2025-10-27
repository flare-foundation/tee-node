package settings_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/stretchr/testify/require"
)

func TestInitialUrlNotSet(t *testing.T) {
	// Create and start the proxy config server
	server := settings.NewConfigServer(3000, nil)
	go server.Serve()                        //nolint:errcheck
	defer server.Close(context.Background()) //nolint:errcheck

	time.Sleep(100 * time.Millisecond)

	server.ProxyURL.RLock()
	defer server.ProxyURL.RUnlock()
	require.Equal(t, "", server.ProxyURL.URL)
}

func TestInitialUrlSet(t *testing.T) {
	// Create a new ProxyURLMutex instance

	err := os.Setenv("PROXY_URL", "http://envproxy.com")
	require.NoError(t, err)
	defer os.Unsetenv("PROXY_URL") //nolint:errcheck

	// Create and start the proxy config server
	server := settings.NewConfigServer(3001, nil)
	go server.Serve()                        //nolint:errcheck
	defer server.Close(context.Background()) //nolint:errcheck

	time.Sleep(100 * time.Millisecond)

	server.ProxyURL.RLock()
	defer server.ProxyURL.RUnlock()
	require.Equal(t, "http://envproxy.com", server.ProxyURL.URL)
}

func TestEndpointUrlSet(t *testing.T) {
	// Create and start the proxy config server
	server := settings.NewConfigServer(3002, nil)
	go server.Serve()                        //nolint:errcheck
	defer server.Close(context.Background()) //nolint:errcheck

	time.Sleep(100 * time.Millisecond)
	// Prepare request
	payload := map[string]string{"url": "http://newproxy.com"}
	data, err := json.Marshal(payload)
	require.NoError(t, err)

	resp, err := http.Post("http://localhost:3002/proxy", "application/json", bytes.NewBuffer(data))
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	err = resp.Body.Close()
	require.NoError(t, err)

	server.ProxyURL.RLock()
	defer server.ProxyURL.RUnlock()
	require.Equal(t, "http://newproxy.com", server.ProxyURL.URL)
}
