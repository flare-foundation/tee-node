package settings

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/tee-node/pkg/types"
)

type ProxyURLMutex struct {
	URL string

	sync.RWMutex
}

type ProxyConfigureServer struct {
	server *http.Server

	ProxyURL *ProxyURLMutex
}

type Configurer interface {
	SetOwner(common.Address) error
	SetExtensionID(common.Hash) error
}

// NewConfigServer creates an HTTP server that accepts proxy configuration
// requests on the provided port and exposes the configured URL via ProxyUrl.
func NewConfigServer(port int, configurer Configurer) *ProxyConfigureServer {
	proxyUrl := &ProxyURLMutex{}
	proxyUrl.setProxyURLFromEnv()

	addr := fmt.Sprintf(":%d", port)
	server := &http.Server{
		Addr: addr,
	}
	mux := http.NewServeMux()
	server.Handler = mux
	mux.HandleFunc("POST "+SetProxyURLEndpoint, proxyUrl.setProxyURL)
	mux.HandleFunc("POST "+SetInitialOwnerEndpoint, initialOwnerHandler(configurer))
	mux.HandleFunc("POST "+SetExtensionIDEndpoint, extensionIDHandler(configurer))

	pc := ProxyConfigureServer{
		server:   server,
		ProxyURL: proxyUrl,
	}

	return &pc
}

// setProxyURLFromEnv sets the proxy url from the environment variable PROXY_URL if it was not already set.
func (u *ProxyURLMutex) setProxyURLFromEnv() {
	u.Lock()
	defer u.Unlock()

	if u.URL != "" {
		return
	}

	u.URL = os.Getenv(ProxyURLEnvVar)
}

// Serve starts the proxy configuration server and blocks until it stops.
func (pc *ProxyConfigureServer) Serve() error {
	return pc.server.ListenAndServe()
}

// Close gracefully shuts down the proxy configuration server.
func (pc *ProxyConfigureServer) Close(ctx context.Context) error {
	return pc.server.Shutdown(ctx)
}

// setProxyURL handles requests to /proxy.
func (u *ProxyURLMutex) setProxyURL(w http.ResponseWriter, r *http.Request) {
	var request types.ConfigureProxyURLRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&request)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	_, err = url.ParseRequestURI(request.URL)
	if err != nil {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	u.Lock()
	defer u.Unlock()

	u.URL = request.URL

	w.WriteHeader(http.StatusOK)
}

// extensionIDHandler returns a handler of requests to /extension-id.
func extensionIDHandler(configurer Configurer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request types.ConfigureExtensionIDRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&request)
		if err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		err = configurer.SetExtensionID(request.ExtensionID)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to set extension ID: %v", err), http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

// extensionIDHandler returns a handler of requests to /initial-owner.
func initialOwnerHandler(configurer Configurer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request types.ConfigureInitialOwnerRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&request)
		if err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		err = configurer.SetOwner(request.Owner)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to set initial owner: %v", err), http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}
