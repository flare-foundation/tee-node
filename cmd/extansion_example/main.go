package main

import (
	"errors"
	"log"
	"net/http"

	exampleextension "github.com/flare-foundation/tee-node/internal/extension/example_extension"
)

func main() {
	server := exampleextension.NewDummyExtensionServer(8888, 8889)

	if err := server.Serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("Server error: %v", err)
	}
}
