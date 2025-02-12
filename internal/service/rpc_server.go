package service

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"tee-node/internal/service/attestationservice"
	"tee-node/internal/service/nodeservice"
	"tee-node/internal/service/policyservice"
	"tee-node/internal/service/walletsservice"

	"github.com/ethereum/go-ethereum/rpc"
)

func LaunchServer(port int) {
	// Create a new RPC server
	server := rpc.NewServer()

	// Register services
	err := server.RegisterName("policyservice", policyservice.NewService())
	if err != nil {
		log.Fatalf("Failed to register policy service: %v", err)
	}
	err = server.RegisterName("attestaionservice", attestationservice.NewService())
	if err != nil {
		log.Fatalf("Failed to register attestation service: %v", err)
	}
	err = server.RegisterName("walletsservice", walletsservice.NewService())
	if err != nil {
		log.Fatalf("Failed to register wallets service: %v", err)
	}
	err = server.RegisterName("nodeservice", nodeservice.NewService())
	if err != nil {
		log.Fatalf("Failed to register node service: %v", err)
	}

	listener, err := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(port))
	if err != nil {
		log.Fatalf("Failed to start listener: %v", err)
	}
	fmt.Println("JSON-RPC server listening on 0.0.0.0:" + strconv.Itoa(port))

	// Create a channel to listen for OS signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Run the server in a goroutine
	go func() {
		if err := http.Serve(listener, server); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server ListenAndServe: %v", err)
		}
	}()

	// Block until a signal is received
	sig := <-sigCh
	fmt.Printf("Received signal %s, shutting down...\n", sig)

	// Gracefully shut down the server
	if err := listener.Close(); err != nil {
		log.Fatalf("Failed to close listener: %v", err)
	}
}
