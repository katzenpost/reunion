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

func TestDeterministicSession(t *testing.T) {
	dsessionCtidhSkBytes, err := hex.DecodeString("010001feff000200ff000000fd00000200feff01fffe00030000fffe00ffffffffff00fc0000fe02fe000000000001fe0001fe00ff0101020001000100ff00ffff00020000ff0100fd00000101fffe010002000001ff0002ff0001ff000100ff0201000000000200ff000000fffe0001ff0002fe000000000100010000ff00000000")
	require.NoError(t, err)
	dsessionCtidhPkBytes, err := hex.DecodeString("2a6a622e79b73b4f7310e592a06088afd5d8e74cafb931dc9805db8269ac04427c6a1ff1c7058a1e8391a58ddc7d5a5ee8133b07c97e7ef85986934c9c01e5c05aaf77e6bf99f7c59eef4f3c81c3ecf264c41d538ae540c7f2fce92b2df6abe9fa5aa864912b4a19931d2be70407f2b3b46e8c88d077cf2eb603f9dfa2276a08")
	require.NoError(t, err)

	csidhPk := &[csidhPubKeyLen]byte{}
	copy(csidhPk[:], dsessionCtidhPkBytes)
	csidhSk := &[csidhPrivKeyLen]byte{}
	copy(csidhSk[:], dsessionCtidhSkBytes)

	passphrase, err := hex.DecodeString("9b0ac4fbd2e84a047b40695c391664890e570ee302a22c16c7025f52ed0586db")
	require.NoError(t, err)

	alicePayload, err := hex.DecodeString("00b7bf81a81bea5506669e6c00646beead875b9b1c5a8f30ea4a11ccf6ce2a98")
	require.NoError(t, err)

	bobPayload, err := hex.DecodeString("5c0d6c7b18d41aa1bb35dcf72f91bf9da292278c6057c8525df7e76ee4fa0764")
	require.NoError(t, err)

	seed, err := hex.DecodeString("1234")
	require.NoError(t, err)

	aliceSession := CreateDeterministicSesson(passphrase, alicePayload, seed, csidhPk, csidhSk)
	at1, err := aliceSession.T1.MarshalBinary()
	require.NoError(t, err)

	expectedAt1, err := hex.DecodeString("b7e50c69c1576ac0c38aa770facf18f86e837de3a265ba1b6776a4d64526c546214e6df3a72dad41d7218a65a691198ec1d13c040b100abbd8f72519bcfe597bc5b7012111e8b0e4bd59037650c24c047677ccccbe6f0230730ba7735edb73f03aee4c4115c4f0c9376d4ce59d311e90391fa65061df52d7ac6b4cd09b7e93a530a6fef8ddc407f67323ee079abe15669e9b15d9d4fec0e542ff69994234c609520e55fc3d434366794d59a0d672d7fd3dbad2eed6713de60de1098dc99bc2d24b24d1fdedb856c9104690350d0917d173de3ff6d4d5e6957305cd761eb4bdc2")
	require.NoError(t, err)
	t.Logf("Alice T1: %x", at1)
	require.Equal(t, at1, expectedAt1)

	bobSession := CreateDeterministicSesson(passphrase, bobPayload, seed, csidhPk, csidhSk)
	bt1, err := bobSession.T1.MarshalBinary()
	require.NoError(t, err)

	expectedBt1, err := hex.DecodeString("54ad5d6ca02c133782ffbbc26027d6d096ffb48c0df8c4bc469ba7b50881ea6bce6f8ba1e460862933a85b9b6a190adc6648cdd61a648e570d1b34b7e5830057c8117e95c57d7c1da083ad9d39ec2c367856b8dbe164f7f964c53da076f690edb1e8f4e276e757e074545eda23a60397227cf5d8d63d4ded364d01042402b9c0135cf19897d79ec764a37c579ebf3aaaee10926238dc06bc4d7b89b3b67cd7046b350f40fbb821fae6ec563366f419de62d3bdef94405a6f39595342fcb9fa6261185db123cd0e1d367097cf80f47f0acb9ba73062f605abc187556b65a9bc23")
	require.NoError(t, err)
	require.Equal(t, bt1, expectedBt1)
}
