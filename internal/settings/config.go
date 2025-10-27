package settings

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/flare-foundation/tee-node/pkg/node"
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

// NewConfigServer creates an HTTP server that accepts proxy configuration
// requests on the provided port and exposes the configured URL via ProxyUrl.
func NewConfigServer(port int, configurer node.Configurer) *ProxyConfigureServer {
	proxyUrl := &ProxyURLMutex{}
	proxyUrl.setProxyURLFromEnv()

	addr := fmt.Sprintf(":%d", port)
	server := &http.Server{
		Addr: addr,
	}
	mux := http.NewServeMux()
	server.Handler = mux
	mux.HandleFunc("POST /proxy", proxyUrl.setProxyURL)
	mux.HandleFunc("POST /initial-owner", initialOwnerHandler(configurer))
	mux.HandleFunc("POST /extension-id", extensionIDHandler(configurer))

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

	initialProxyUrl := os.Getenv("PROXY_URL")
	if initialProxyUrl != "" {
		u.URL = initialProxyUrl
	}
}

// Serve starts the proxy configuration server and blocks until it stops.
func (pc *ProxyConfigureServer) Serve() error {
	return pc.server.ListenAndServe()
}

// Close gracefully shuts down the proxy configuration server.
func (pc *ProxyConfigureServer) Close(ctx context.Context) error {
	return pc.server.Shutdown(ctx)
}

func (u *ProxyURLMutex) setProxyURL(w http.ResponseWriter, r *http.Request) {
	var request types.ConfigureProxyURLRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	u.Lock()
	defer u.Unlock()

	u.URL = request.URL

	w.WriteHeader(http.StatusOK)
}

func extensionIDHandler(configurer node.Configurer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request types.ConfigureExtensionIDRequest
		err := json.NewDecoder(r.Body).Decode(&request)
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
func initialOwnerHandler(configurer node.Configurer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request types.ConfigureInitialOwnerRequest
		err := json.NewDecoder(r.Body).Decode(&request)
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
