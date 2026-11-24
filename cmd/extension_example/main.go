package main

import (
	"errors"
	"log"
	"net/http"

	"github.com/flare-foundation/fcc-node/internal/testutils"
)

func main() {
	server := testutils.NewDummyExtensionServer(8888, 8889)

	if err := server.Serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("Server error: %v", err)
	}
}
