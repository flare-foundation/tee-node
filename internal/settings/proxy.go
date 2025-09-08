package settings

import (
	"encoding/json"
	"fmt"
	"net/http"
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

	mux := http.NewServeMux()
	server.Handler = mux
	mux.HandleFunc("POST /configure", setProxyURL)

	for {
		err := server.ListenAndServe()
		if err != nil {
			logger.Errorf("error serving proxy url config: %v", err)
		}

		time.Sleep(time.Second)
	}
}

func setProxyURL(w http.ResponseWriter, r *http.Request) {
	var request types.ConfigureProxyUrlRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	ProxyURL.Lock()
	defer ProxyURL.Unlock()

	ProxyURL.URL = request.Url
}
