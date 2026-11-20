package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// A result's data travels as base64, and its hash is over the decoded bytes,
// so a decoded result verifies the same as the one signed.
func TestActionResultDataIsBase64(t *testing.T) {
	result := ActionResult{Status: 1, Data: []byte(`{"a":1}`)}

	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"data":"eyJhIjoxfQ=="`)

	var decoded ActionResult
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, result.Data, decoded.Data)
	require.Equal(t, result.Hash(), decoded.Hash())

	// hex is refused rather than misread
	require.Error(t, json.Unmarshal([]byte(`{"data":"0x7b7d"}`), &decoded))
}
