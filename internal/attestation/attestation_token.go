package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/attestation"
)

// GetGoogleAttestationToken retrieves an attestation token for the supplied
// nonces and token type, short-circuiting to MagicPass outside production.
func GetGoogleAttestationToken(nonces []string, tokenType attestation.TokenType) ([]byte, error) {
	if settings.Mode != 0 {
		return []byte(attestation.MagicPass), nil
	}
	httpClient := http.Client{
		Transport: &http.Transport{
			// Set the DialContext field to a function that creates
			// a new network connection to a Unix domain socket
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", "/run/container_launcher/teeserver.sock")
			},
		},
	}

	// Get the token from the IPC endpoint
	url := "http://localhost/v1/token"

	type TokenRequest struct {
		Audience  string   `json:"audience"`
		TokenType string   `json:"token_type"`
		Nonces    []string `json:"nonces"`
	}

	data := TokenRequest{
		Audience:  "https://sts.google.com",
		TokenType: string(tokenType),
		Nonces:    nonces,
	}

	requestBody, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Post(url, "application/json", strings.NewReader(string(requestBody)))
	if err != nil {
		return nil, fmt.Errorf("failed to get raw token response: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	tokenBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token body: %w", err)
	}

	return tokenBytes, nil
}

// CreateAttestation returns the attestation token as a string for convenience.
func CreateAttestation(nonces []string, tokenType attestation.TokenType) (string, error) {
	var tokenBytes []byte
	var err error
	tokenBytes, err = GetGoogleAttestationToken(nonces, tokenType)
	if err != nil {
		return "", err
	}

	return string(tokenBytes), nil
}
