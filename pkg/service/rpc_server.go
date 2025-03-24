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

	"tee-node/pkg/service/instructionservice"
	"tee-node/pkg/service/nodeservice"
	"tee-node/pkg/service/policyservice"

	"github.com/ethereum/go-ethereum/rpc"
)

func LaunchServer(port int) {
	// Create a new RPC server
	server := rpc.NewServer()

	// Register services
	if err := server.RegisterName("instructionservice", instructionservice.NewService()); err != nil {
		log.Fatalf("Failed to register instruction service: %v", err)
	}
	if err := server.RegisterName("policyservice", policyservice.NewService()); err != nil {
		log.Fatalf("Failed to register policy service: %v", err)
	}
	if err := server.RegisterName("nodeservice", nodeservice.NewService()); err != nil {
		log.Fatalf("Failed to register policy service: %v", err)
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
