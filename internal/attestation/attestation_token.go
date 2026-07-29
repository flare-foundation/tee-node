package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/attestation"
)

// attestationClient is a shared HTTP client for the launcher's teeserver unix
// socket. It is reused across calls so idle connections (and the goroutines
// backing them) are pooled and eventually closed, rather than leaking one
// connection plus goroutines per attestation request.
var attestationClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		// Dial the launcher's teeserver Unix domain socket.
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", "/run/container_launcher/teeserver.sock")
		},
	},
}

// GetGoogleAttestationToken retrieves an attestation token for the supplied
// nonces and token type, short-circuiting to MagicPass outside production.
func GetGoogleAttestationToken(nonces []string, tokenType attestation.TokenType) ([]byte, error) {
	if settings.Mode != 0 {
		return []byte(attestation.MagicPass), nil
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

	resp, err := attestationClient.Post(url, "application/json", strings.NewReader(string(requestBody)))
	if err != nil {
		return nil, fmt.Errorf("failed to get raw token response: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	tokenBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %s: %s", resp.Status, string(tokenBytes))
	}

	return tokenBytes, nil
}
