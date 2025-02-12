package attestationservice

import (
	"context"
	"fmt"
	api "tee-node/api/types"
	"testing"
)

func TestGetAttestationToken(t *testing.T) {
	req := api.GetAttestationTokenRequest{
		Nonces: []string{"bla"},
	}

	attestationService := NewService()

	response, err := attestationService.GetAttestationToken(context.Background(), &req)
	if err != nil {
		// t.Errorf("Failed to initialize the policy: %v", err)
		println("!!!This only works if the server is running in a GCP confidential space")
	}

	fmt.Printf("Response: %v\n", response)
}
