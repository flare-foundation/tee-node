package fdc

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	csigning "github.com/flare-foundation/go-flare-common/pkg/signing"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/fdc2"
	"github.com/stretchr/testify/require"
)

// TestPerBodyHash_MatchesSolidity verifies the per-piece hash identity
// HashMessage relies on: keccak256(raw_body_bytes) equals Solidity's
// keccak256(abi.encode(body_struct)) for both dynamic and static body
// schemas, and the full messageHash matches end-to-end.
func TestPerBodyHash_MatchesSolidity(t *testing.T) {
	requestArg := fdc2.AttestationTypeArguments[fdc2.PMWMultisigAccountConfigured].Request
	pmwRequest := fdc2.IPMWMultisigAccountConfiguredRequestBody{
		AccountAddress: "rJSWVX9tLrogbBQQXzJML3NmtrAZwuxzUB",
		PublicKeys:     [][]byte{{0xa1, 0xb2}, {0xc3, 0xd4, 0xe5}},
		Threshold:      1,
	}
	solRequestEnc, err := abi.Arguments{requestArg}.Pack(pmwRequest)
	require.NoError(t, err)
	solRequestHash := crypto.Keccak256Hash(solRequestEnc)

	requestBytes, err := structs.Encode(requestArg, pmwRequest)
	require.NoError(t, err)
	directDynamicHash := crypto.Keccak256Hash(requestBytes)
	require.Equal(t, solRequestHash, directDynamicHash,
		"direct keccak256 of body bytes must equal Solidity keccak256(abi.encode(struct))")

	bytesTy, err := abi.NewType("bytes", "", nil)
	require.NoError(t, err)
	wrappedReq, err := (abi.Arguments{{Type: bytesTy}}).Pack(requestBytes)
	require.NoError(t, err)
	require.NotEqual(t, solRequestHash, crypto.Keccak256Hash(wrappedReq),
		"bytesArgs.Pack wrapping must not coincidentally equal Solidity hash")

	responseArg := fdc2.AttestationTypeArguments[fdc2.PMWMultisigAccountConfigured].Response
	pmwResponse := fdc2.IPMWMultisigAccountConfiguredResponseBody{Status: 0, Sequence: 17921259}
	solResponseEnc, err := abi.Arguments{responseArg}.Pack(pmwResponse)
	require.NoError(t, err)
	solResponseHash := crypto.Keccak256Hash(solResponseEnc)

	responseBytes, err := structs.Encode(responseArg, pmwResponse)
	require.NoError(t, err)
	require.Equal(t, solResponseHash, crypto.Keccak256Hash(responseBytes),
		"direct keccak256 of static body bytes must equal Solidity keccak256(abi.encode(struct))")

	header := fdc2.IFdc2HubFdc2ResponseHeader{
		AttestationType:    [32]byte{0x01},
		SourceId:           [32]byte{0x02},
		ThresholdBIPS:      0,
		ProofOwner:         common.HexToAddress("0xdead"),
		Cosigners:          []common.Address{common.HexToAddress("0x1")},
		CosignersThreshold: 1,
		Timestamp:          1718113274,
	}
	encHeader, err := EncodeResponseHeader(header)
	require.NoError(t, err)
	headerHash := crypto.Keccak256Hash(encHeader)

	bytes32Ty, err := abi.NewType("bytes32", "", nil)
	require.NoError(t, err)
	uint256Ty, err := abi.NewType("uint256", "", nil)
	require.NoError(t, err)

	dataInner, err := abi.Arguments{{Type: bytes32Ty}, {Type: bytes32Ty}, {Type: bytes32Ty}}.Pack(
		[32]byte(headerHash), [32]byte(solRequestHash), [32]byte(solResponseHash),
	)
	require.NoError(t, err)
	expectedDataHash := crypto.Keccak256Hash(dataInner)

	domainEnc, err := abi.Arguments{{Type: bytes32Ty}, {Type: uint256Ty}, {Type: bytes32Ty}}.Pack(
		[32]byte(csigning.FDC2), new(big.Int).SetUint64(31337), [32]byte(expectedDataHash),
	)
	require.NoError(t, err)
	expectedMsgHash := crypto.Keccak256Hash(domainEnc)

	req := fdc2.IFdc2HubFdc2AttestationRequest{
		Header: fdc2.IFdc2HubFdc2RequestHeader{
			AttestationType: header.AttestationType,
			SourceId:        header.SourceId,
			ThresholdBIPS:   header.ThresholdBIPS,
			ProofOwner:      header.ProofOwner,
		},
		RequestBody: requestBytes,
	}
	msgHash, _, err := HashMessage(31337, req, responseBytes, header.Cosigners, header.CosignersThreshold, header.Timestamp)
	require.NoError(t, err)
	require.Equal(t, expectedMsgHash, msgHash,
		"HashMessage must produce the same messageHash the contract derives")
}
