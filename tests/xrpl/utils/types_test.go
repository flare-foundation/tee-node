package utils_test

import (
	"encoding/hex"
	"testing"

	xrplutils "github.com/flare-foundation/tee-node/tests/xrpl/utils"

	"github.com/stretchr/testify/require"
)

func TestDeriveAddress(t *testing.T) {
	pubKeys := []string{
		"02707A7AE05A8DACDB89CC93429949CDA26F68200D9CE8753D4DCB04D6F80CFCB7",
		"035DB05B1CEA82785FB8B3F7E68E5C7429A1B00BE47CC6B1A651AA12C7B8D9592C",
		"030C141E3E131B1D25B7EA85B10283E315F77F27A2FA085A45D65D47393DB9219F",
	}
	addresses := []string{
		"rN5N6fJbc8xyViPDeQFMQMpYfVHuxSGV2G",
		"rJQesZZEQzW9J3Eb1X1Snc7E6YGk7kTMoK",
		"r9cvJhquqeExszdWZSw2rrFP98fsVFLdPe",
	}

	for i, pubKey := range pubKeys {
		pkBytes, _ := hex.DecodeString(pubKey)
		pubKey := xrplutils.PublicKey(pkBytes)

		require.Equal(t, addresses[i], pubKey.Address())
	}
}
