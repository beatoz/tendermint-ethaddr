package secp256k1

import (
	"encoding/hex"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto"
	"testing"
)

func Test_EthAddr(t *testing.T) {
	privateKey, err := hex.DecodeString("83b8749ffd3b90bb26bdfa430f8df21d881df9962eb96b4ee68b3f60c57c5ccb")
	require.NoError(t, err)
	expectedEthAddr, err := hex.DecodeString("44087362E1d64596743a3d4Ac3CFE874544CA7fa")
	require.NoError(t, err)
	expectedBtcAddr, err := hex.DecodeString("7612536BD0991DB67E60DA9ECA1E3E276889B8DC")
	require.NoError(t, err)

	pubKey := PrivKey(privateKey).PubKey()

	ethAddr0 := ethAddress(pubKey.Bytes())
	require.EqualValues(t, crypto.Address(expectedEthAddr), ethAddr0)
	ethAddr1 := pubKey.Address()
	require.EqualValues(t, crypto.Address(expectedEthAddr), ethAddr1)

	btcAddr := btcAddress(pubKey.Bytes())
	require.EqualValues(t, crypto.Address(expectedBtcAddr), btcAddr)
}
