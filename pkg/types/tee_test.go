package types_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/verification"
	"github.com/flare-foundation/tee-node/pkg/types"
)

// TestEncodeTeeAttestationRequestGolden pins the encoding to Solidity's
// abi.encode(IVerification.TeeAttestation), written out word by word.
func TestEncodeTeeAttestationRequestGolden(t *testing.T) {
	req := verification.IVerificationTeeAttestation{
		TeeMachine: verification.IMachineManagerTeeMachineWithAttestationData{
			TeeId:        common.HexToAddress("0x00000000000000000000000000000000000000aa"),
			InitialTeeId: common.HexToAddress("0x00000000000000000000000000000000000000bb"),
			Url:          "tee.example",
			CodeHash:     [32]byte(common.HexToHash("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")),
			Platform:     [32]byte(common.HexToHash("0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")),
		},
		Challenge: [32]byte(common.HexToHash("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")),
	}

	want, err := hex.DecodeString(strings.Join([]string{
		"0000000000000000000000000000000000000000000000000000000000000020", // offset of TeeAttestation
		"0000000000000000000000000000000000000000000000000000000000000040", // offset of teeMachine
		"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", // challenge
		"00000000000000000000000000000000000000000000000000000000000000aa", // teeId
		"00000000000000000000000000000000000000000000000000000000000000bb", // initialTeeId
		"00000000000000000000000000000000000000000000000000000000000000a0", // offset of url
		"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", // codeHash
		"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", // platform
		"000000000000000000000000000000000000000000000000000000000000000b", // len(url)
		"7465652e6578616d706c65000000000000000000000000000000000000000000", // url
	}, ""))
	require.NoError(t, err)

	got, err := types.EncodeTeeAttestationRequest(&req)
	require.NoError(t, err)
	require.Equal(t, want, []byte(got))

	decoded, err := types.DecodeTeeAttestationRequest(want)
	require.NoError(t, err)
	require.Equal(t, req, decoded)
}

func TestEncodeTeeAttestationRequestNil(t *testing.T) {
	_, err := types.EncodeTeeAttestationRequest(nil)
	require.Error(t, err)
}
