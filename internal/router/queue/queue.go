// queue package implements functions for interacting with proxy's internal endpoints.
package queue

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/types"
)

// FetchAction sends an empty POST request to the url and expect an action as a response.
func FetchAction(url string) (*types.Action, error) {
	client := http.Client{
		Timeout: settings.ProxyTimeout,
	}
	res, err := client.Post(url, "", nil)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d, response: %s", res.StatusCode, string(body))
	}

	var response types.Action
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

// PostActionResponse sends POST request with response in body to url.
func PostActionResponse(url string, response *types.ActionResponse) error {
	client := http.Client{
		Timeout: settings.ProxyTimeout,
	}
	requestBody, err := json.Marshal(response)
	if err != nil {
		return err
	}
	res, err := client.Post(url, "application/json", bytes.NewReader(requestBody))
	if err != nil {
		return err
	}

	defer res.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d, response: %s", res.StatusCode, string(body))
	}

	return nil
}
