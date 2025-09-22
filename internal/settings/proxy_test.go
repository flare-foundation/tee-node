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
	server := settings.NewProxyConfigServer(3000)
	go server.Serve()                        //nolint:errcheck
	defer server.Close(context.Background()) //nolint:errcheck

	time.Sleep(100 * time.Millisecond)

	server.ProxyUrl.RLock()
	defer server.ProxyUrl.RUnlock()
	require.Equal(t, "", server.ProxyUrl.URL)
}

func TestInitialUrlSet(t *testing.T) {
	// Create a new ProxyURLMutex instance

	err := os.Setenv("PROXY_URL", "http://envproxy.com")
	require.NoError(t, err)
	defer os.Unsetenv("PROXY_URL") //nolint:errcheck

	// Create and start the proxy config server
	server := settings.NewProxyConfigServer(3001)
	go server.Serve()                        //nolint:errcheck
	defer server.Close(context.Background()) //nolint:errcheck

	time.Sleep(100 * time.Millisecond)

	server.ProxyUrl.RLock()
	defer server.ProxyUrl.RUnlock()
	require.Equal(t, "http://envproxy.com", server.ProxyUrl.URL)
}

func TestEndpointUrlSet(t *testing.T) {
	// Create and start the proxy config server
	server := settings.NewProxyConfigServer(3002)
	go server.Serve()                        //nolint:errcheck
	defer server.Close(context.Background()) //nolint:errcheck

	time.Sleep(100 * time.Millisecond)
	// Prepare request
	payload := map[string]string{"url": "http://newproxy.com"}
	data, err := json.Marshal(payload)
	require.NoError(t, err)

	resp, err := http.Post("http://localhost:3002/configure", "application/json", bytes.NewBuffer(data))
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	err = resp.Body.Close()
	require.NoError(t, err)

	server.ProxyUrl.RLock()
	defer server.ProxyUrl.RUnlock()
	require.Equal(t, "http://newproxy.com", server.ProxyUrl.URL)
}
