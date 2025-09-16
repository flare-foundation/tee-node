package settings

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/flare-foundation/tee-node/pkg/types"
)

var ProxyURL ProxyURLMutex

type ProxyURLMutex struct {
	URL string

	sync.RWMutex
}

func ProxyURLConfigServer(port int) {
	addr := fmt.Sprintf(":%d", port)

	server := &http.Server{
		Addr: addr,
	}

	setInitialProxyUrl()

	mux := http.NewServeMux()
	server.Handler = mux
	mux.HandleFunc("POST /configure", handleConfigure)

	for {
		err := server.ListenAndServe()
		if err != nil {
			logger.Errorf("error serving proxy url config: %v", err)
		}

		time.Sleep(time.Second)
	}
}

func setInitialProxyUrl() {
	initialProxyUrl := os.Getenv("PROXY_URL")
	if initialProxyUrl != "" {
		setProxyUrl(initialProxyUrl)
	}
}

func handleConfigure(w http.ResponseWriter, r *http.Request) {
	var request types.ConfigureProxyUrlRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	setProxyUrl(request.Url)
}

func setProxyUrl(proxyUrl string) {
	ProxyURL.Lock()
	defer ProxyURL.Unlock()

	ProxyURL.URL = proxyUrl

	logger.Infof("Setting proxy url to: %s", proxyUrl)
}
