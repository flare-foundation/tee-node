package attestation

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"tee-node/internal/node"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func GetGoogleAttestationToken(nonces []string) ([]byte, error) {
	httpClient := http.Client{
		Transport: &http.Transport{
			// Set the DialContext field to a function that creates
			// a new network connection to a Unix domain socket
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", "/run/container_launcher/teeserver.sock")
			},
		},
	}

	nonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to create nonce: %w", err)
	}

	nodeId := node.GetNodeId()
	timeNow := strconv.Itoa(int(time.Now().Unix()))

	noncesAll := append(nonces, nodeId.Uuid, timeNow, string(nonce))

	// Get the token from the IPC endpoint
	url := "http://localhost/v1/token"

	type TokenRequest struct {
		Audience  string   `json:"audience"`
		TokenType string   `json:"token_type"`
		Nonces    []string `json:"nonces"`
	}

	data := TokenRequest{
		Audience:  "https://sts.google.com",
		TokenType: "OIDC",
		Nonces:    noncesAll,
	}

	requestBody, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error:", err)
		return nil, status.Error(codes.Aborted, err.Error())
	}

	resp, err := httpClient.Post(url, "application/json", strings.NewReader(string(requestBody)))
	if err != nil {
		return nil, fmt.Errorf("failed to get raw token response: %w", err)
	}
	tokenbytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token body: %w", err)
	}

	return tokenbytes, nil
}
