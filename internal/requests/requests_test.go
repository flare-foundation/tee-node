package requests_test

import (
	"tee-node/internal/requests"
	"tee-node/internal/utils"
	"tee-node/internal/wallets"
	testutils "tee-node/tests"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const walletName = "wallet1"

func TestInvalidRequestSignature(t *testing.T) {

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, _ = testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	newWalletRequest := wallets.NewNewWalletRequest(walletName)

	wrongPrivKey, err := utils.GenerateEthereumPrivateKey()
	require.NoError(t, err)

	wrongSig, err := requests.Sign(newWalletRequest, wrongPrivKey)
	require.NoError(t, err)

	_, err = requests.CheckSignature(newWalletRequest, wrongSig)

	if assert.Error(t, err) {
		assert.Equal(t, "not a voter", err.Error())
	}

}
