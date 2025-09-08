package extension

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/types"
)

// PostActionToExtension sends POST request with response in body to url.
func PostActionToExtension(url string, action *types.Action) (*types.ActionResult, error) {
	client := http.Client{
		Timeout: settings.ProxyTimeout,
	}

	requestBody, err := json.Marshal(action)
	if err != nil {
		return nil, err
	}
	res, err := client.Post(url, "application/json", bytes.NewReader(requestBody))
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

	result := new(types.ActionResult)
	err = json.Unmarshal(body, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
