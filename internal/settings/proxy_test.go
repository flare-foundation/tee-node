package settings_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/stretchr/testify/require"
)

func TestInitialUrlNotSet(t *testing.T) {
	// Reset state
	settings.ProxyURL = settings.ProxyURLMutex{}

	go settings.ProxyURLConfigServer(3000)

	settings.ProxyURL.RLock()
	defer settings.ProxyURL.RUnlock()
	require.Equal(t, "", settings.ProxyURL.URL)
}

func TestInitialUrlSet(t *testing.T) {
	// Reset state
	settings.ProxyURL = settings.ProxyURLMutex{}

	err := os.Setenv("PROXY_URL", "http://envproxy.com")
	require.NoError(t, err)
	defer os.Unsetenv("PROXY_URL") //nolint:errcheck

	go settings.ProxyURLConfigServer(3001)

	time.Sleep(100 * time.Millisecond)

	settings.ProxyURL.RLock()
	defer settings.ProxyURL.RUnlock()
	require.Equal(t, "http://envproxy.com", settings.ProxyURL.URL)
}

func TestEndpointUrlSet(t *testing.T) {
	// Reset state
	settings.ProxyURL = settings.ProxyURLMutex{}

	// os.Setenv("PROXY_URL", "ABC")
	go settings.ProxyURLConfigServer(3002)

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

	settings.ProxyURL.RLock()
	defer settings.ProxyURL.RUnlock()
	require.Equal(t, "http://newproxy.com", settings.ProxyURL.URL)
}
