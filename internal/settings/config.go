package settings

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/flare-foundation/tee-node/pkg/types"
)

type ProxyURLMutex struct {
	URL string

	sync.RWMutex
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

type ConfigServer struct {
	server   *http.Server
	ProxyURL *ProxyURLMutex
}

type Configurer interface {
	SetOwner(common.Address) error
	SetExtensionID(common.Hash) error
	SetChainID(uint64) error
	SetGovernance(signers []common.Address, threshold uint64) error
}

// NewConfigServer creates an HTTP server that accepts proxy configuration
// requests on the provided port and exposes the configured URL via ProxyURL.
func NewConfigServer(port int, configurer Configurer) *ConfigServer {
	proxyURL := &ProxyURLMutex{}
	proxyURL.setProxyURLFromEnv()

	addr := fmt.Sprintf(":%d", port)
	server := &http.Server{
		Addr:              addr,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		MaxHeaderBytes:    2 << 10, // 2 KiB
	}

	mux := http.NewServeMux()
	server.Handler = limitRequestBody(mux, maxConfigBodyBytes)
	mux.HandleFunc("POST "+SetProxyURLEndpoint, proxyURL.proxyHandler)
	mux.HandleFunc("POST "+SetInitialOwnerEndpoint, initialOwnerHandler(configurer))
	mux.HandleFunc("POST "+SetExtensionIDEndpoint, extensionIDHandler(configurer))
	mux.HandleFunc("POST "+SetChainIDEndpoint, chainIDHandler(configurer))
	mux.HandleFunc("POST "+SetGovernanceEndpoint, governanceHandler(configurer))

	pc := ConfigServer{
		server:   server,
		ProxyURL: proxyURL,
	}

	return &pc
}

// Serve starts the proxy configuration server and blocks until it stops.
func (pc *ConfigServer) Serve() error {
	logger.Infof("Config server listening at %v.", pc.server.Addr)
	return pc.server.ListenAndServe()
}

// Close gracefully shuts down the proxy configuration server.
func (pc *ConfigServer) Close(ctx context.Context) error {
	return pc.server.Shutdown(ctx)
}

// maxConfigBodyBytes caps config request bodies. These payloads are tiny (a
// URL, an address, an id, a small signer list), so a small cap removes any
// unbounded-decode allocation without rejecting legitimate requests.
const maxConfigBodyBytes = 64 << 10 // 64 KiB

// limitRequestBody caps each request body via http.MaxBytesReader so an
// oversized POST cannot drive an unbounded JSON-decode allocation; reads past
// the cap fail and the handlers surface them as a 400.
func limitRequestBody(h http.Handler, n int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, n)
		h.ServeHTTP(w, r)
	})
}

// proxyHandler handles requests to /proxy.
func (u *ProxyURLMutex) proxyHandler(w http.ResponseWriter, r *http.Request) {
	var request types.ConfigureProxyURLRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if request.URL == nil {
		http.Error(w, "Missing URL in request", http.StatusBadRequest)
		return
	}

	URL := *request.URL

	_, err := url.ParseRequestURI(URL)
	if err != nil {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	u.Lock()
	defer u.Unlock()

	u.URL = URL

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

		if request.ExtensionID == nil {
			http.Error(w, "Missing extension ID in request", http.StatusBadRequest)
			return
		}

		err = configurer.SetExtensionID(*request.ExtensionID)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to set extension ID: %v", err), http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

// governanceHandler returns a handler of requests to /governance.
func governanceHandler(configurer Configurer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request types.ConfigureGovernanceRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if request.Signers == nil {
			http.Error(w, "Missing signers in request", http.StatusBadRequest)
			return
		}
		if request.Threshold == nil {
			http.Error(w, "Missing threshold in request", http.StatusBadRequest)
			return
		}

		if err := configurer.SetGovernance(*request.Signers, *request.Threshold); err != nil {
			http.Error(w, fmt.Sprintf("Failed to set governance: %v", err), http.StatusForbidden)
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
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if request.Owner == nil {
			http.Error(w, "Missing owner in request", http.StatusBadRequest)
			return
		}

		if err := configurer.SetOwner(*request.Owner); err != nil {
			http.Error(w, fmt.Sprintf("Failed to set initial owner: %v", err), http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

// chainIDHandler returns a handler of requests to /chain-id.
func chainIDHandler(configurer Configurer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request types.ConfigureChainIDRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if request.ChainID == nil {
			http.Error(w, "Missing chain ID in request", http.StatusBadRequest)
			return
		}

		if err := configurer.SetChainID(*request.ChainID); err != nil {
			http.Error(w, fmt.Sprintf("Failed to set chain ID: %v", err), http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}
