package extension

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
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

// FetchState retrieves the extension's node state from its /state route.
//
// Only the extension half of the state is taken from the response. The system
// half is always zeroed, so an extension cannot contribute system state to the
// attestation the TEE signs.
func FetchState(url string) (types.TeeState, error) {
	client := http.Client{
		Timeout: settings.ProxyTimeout,
	}

	res, err := client.Get(url)
	if err != nil {
		return types.TeeState{}, err
	}

	defer res.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(io.LimitReader(res.Body, settings.MaxFetchResponseSize))
	if err != nil {
		return types.TeeState{}, err
	}
	if res.StatusCode != http.StatusOK {
		return types.TeeState{}, fmt.Errorf("unexpected status code: %d, response: %s", res.StatusCode, string(body))
	}

	var state types.TeeState
	err = json.Unmarshal(body, &state)
	if err != nil {
		return types.TeeState{}, err
	}

	return types.TeeState{
		SystemState:        hexutil.Bytes{},
		SystemStateVersion: common.Hash{},
		State:              state.State,
		StateVersion:       state.StateVersion,
	}, nil
}
