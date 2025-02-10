package service

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"tee-node/internal/service/walletsservice"
	"time"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/gorilla/mux"
)

func LaunchWSServer(port int) {
	r := mux.NewRouter()
	r.HandleFunc("/hello", helloHandler)
	r.HandleFunc("/share_wallet", walletsservice.GetShares)
	r.HandleFunc("/recover_wallet", walletsservice.RecoverShare)

	server := &http.Server{
		Addr:         ":" + strconv.Itoa(port),
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 10 * time.Second,
		// TLSConfig: &tls.Config{ServerName: "teenode", ClientAuth: tls.RequireAndVerifyClientCert,
		// 	ClientCAs: caCertPool},
		Handler: r,
	}
	// Gracefuly shutdown server on SIGINT or SIGTERM
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		logger.Infof("ws server starting on %d", port)

		if err := server.ListenAndServe(); err != nil {
			logger.Errorf("failed to serve, %v", err)
		}
		// err = server.ListenAndServeTLS(caFolder+"/tee.crt", caFolder+"/tee.key")

	}()

	<-sigChan
	logger.Info("shutting down ws server...")

}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello!")
}
