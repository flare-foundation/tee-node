package processor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"tee-node/api/types"
	"tee-node/pkg/tee/settings"
)

func getActionInfo(url string) (*types.QueuedActionInfo, error) {
	client := http.Client{
		Timeout: settings.ProxyTimeout,
	}
	res, err := client.Get(url)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d, response: %s", res.StatusCode, string(body))
	}

	var response types.QueuedActionInfo
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func getAction(url string, actionInfo *types.QueuedActionInfo) (*types.QueuedAction, error) {
	client := http.Client{
		Timeout: settings.ProxyTimeout,
	}
	requestBody, err := json.Marshal(actionInfo)
	if err != nil {
		return nil, err
	}
	res, err := client.Post(url, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d, response: %s", res.StatusCode, string(body))
	}

	var response types.QueuedAction
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func postActionResponse(url string, actionResponse *types.QueueActionResponse) error {
	client := http.Client{
		Timeout: settings.ProxyTimeout,
	}
	requestBody, err := json.Marshal(actionResponse)
	if err != nil {
		return err
	}
	res, err := client.Post(url, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return err
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d, response: %s", res.StatusCode, string(body))
	}

	return nil
}
