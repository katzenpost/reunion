package reunion

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
)

var CTIDHPrivateKeyHex string = "01fffd00ff000000ff03ff00fd00ff00fe00000000ffff0100ffff01ff0200ff0100ffff01010001fffffe0001020001010000ff03000100ff00ff0000fd0000fe0003010100ff0302000000ff000000fe000002010001ffff00000000fe03000001ff0001fe010000010000ff00ff0100ffff00010101000000000000000100ff00"

var CTIDHPublicKeyHex string = "a0e897b81374cc17aa917637cda97a56377c9b7bdbe86a53a6f01ce35a0366684568e7de4e38000214a2600ac6a9d07b2379ccccdf0c7ca94ff1288eeb06347101be8cabd24543315eb1d00596d05ebfcde4f13e076bc30635db8aa249b55c992ecb24f9ba128a90b8b1d93420ca8f6454572d4c3b492027b942fb45d1e5a20e"

func TestCTIDHKeysSanityCheck(t *testing.T) {
	s := schemes.ByName("CTIDH1024")
	ctidhPrivateKeyBytes, err := hex.DecodeString(CTIDHPrivateKeyHex)
	require.NoError(t, err)
	privKey, err := s.UnmarshalBinaryPrivateKey(ctidhPrivateKeyBytes)
	require.NoError(t, err)

	ctidhPublicKeyBytes, err := hex.DecodeString(CTIDHPublicKeyHex)
	require.NoError(t, err)
	pubKey, err := s.UnmarshalBinaryPublicKey(ctidhPublicKeyBytes)
	require.NoError(t, err)

	pubKey2 := s.DerivePublicKey(privKey)
	require.Equal(t, pubKey.Bytes(), pubKey2.Bytes())
}

func TestT1Encoding(t *testing.T) {
	g := new(T1)
	_, err := rand.Reader.Read(g.Alpha[:])
	require.NoError(t, err)
	_, err = rand.Reader.Read(g.Beta[:])
	require.NoError(t, err)
	_, err = rand.Reader.Read(g.Gamma[:])
	require.NoError(t, err)
	g.Delta = []byte("lol OMG a test vector that Python doesn't need but golang does.")
	_, err = rand.Reader.Read(g.Delta)
	require.NoError(t, err)
	blob, err := g.MarshalBinary()
	require.NoError(t, err)
	f := new(T1)
	err = f.UnmarshalBinary(blob)
	require.NoError(t, err)
}
