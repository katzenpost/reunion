package reunion

import (
	"crypto/hmac"
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
	dsessionSeed, err := hex.DecodeString("0123456789")
	require.NoError(t, err)
	dsessionSeedA := append([]byte("alice"), dsessionSeed...)
	require.NoError(t, err)
	dsessionSeedB := append([]byte("bob"), dsessionSeed...)
	require.NoError(t, err)

	t.Logf("dsessionSeedA %x", dsessionSeedA)
	t.Logf("dsessionSeedB %x", dsessionSeedB)

	// dsessionPassphrase := []byte("reunion is for rendezvous")
	dsessionGammaSeedA, err := hex.DecodeString("6ba51aada3aca321534d73733860b59ea63a9746dc0bd3b00c09f5eb6feb508a")
	require.NoError(t, err)
	dsessionGammaSeedB, err := hex.DecodeString("75884ac7ad53827bb7bf280bc016191bcdfb6ef80c434e8155ef102e8db258ce")
	require.NoError(t, err)
	dsessionDeltaSeedA, err := hex.DecodeString("d5d0587357083f14ba559f775432b948f30e8e658ff866e2873b7768b3fa8ba5")
	require.NoError(t, err)
	dsessionDeltaSeedB, err := hex.DecodeString("33f1732459211686a4acf28f0cccaa0b8cb9f57b5398765481cd073297a38449")
	require.NoError(t, err)
	dsessionDummySeedA, err := hex.DecodeString("a99f86fb345e9d833ce5534df39beb076f48c4cb62cdb940e23324df510065ea")
	require.NoError(t, err)
	dsessionDummySeedB, err := hex.DecodeString("9e7a7f9f95146604a206a1a577f6d34dc9550054ae635d955eef9b33a8a899b9")
	require.NoError(t, err)
	dsessionTweakA := uint8(32)
	dsessionTweakB := uint8(243)
	dsessionPayloadA, err := hex.DecodeString("f06b1a5db24a0394fb28a53de02059fc34166424e40e64d7a857efdc38f158f1")
	require.NoError(t, err)
	dsessionPayloadB, err := hex.DecodeString("03475cb34f16bceabe4945197cf2a0064eb3a28601fc9489e613debe5e282e1d")
	require.NoError(t, err)
	dsessionAT1, err := hex.DecodeString("e668c52c59cacc162dc6e36dcf42b6ee861a5765b45d8f83c25447c25fb3b49245a65c2972ddf00acf524db29bf9394ce79a17fdb08f1f135dd8b3296d4d83281381b039312a8fbb19a982bea2f55b71e7998c125aeea20eebbbd683b556f35bf250c0b07c7b59251b36610110aa506ddeb8400df688f2560fc9ab8c830786acd47a6e356ae9f9bbece3df3c4b6e083bde2a955fe583e79071c05e834828010496515ab6b675874566529d859a131b50b05bebaa197fe1920b42d1eff6fecc4aac538ab23f58f17b80d131cdb5e112c53c3bd6e4f0cf2df35f1e7d668b2ad1df")
	require.NoError(t, err)
	dsessionAT1Alpha, err := hex.DecodeString("e668c52c59cacc162dc6e36dcf42b6ee861a5765b45d8f83c25447c25fb3b492")
	require.NoError(t, err)
	dsessionAT1Beta, err := hex.DecodeString("45a65c2972ddf00acf524db29bf9394ce79a17fdb08f1f135dd8b3296d4d83281381b039312a8fbb19a982bea2f55b71e7998c125aeea20eebbbd683b556f35bf250c0b07c7b59251b36610110aa506ddeb8400df688f2560fc9ab8c830786acd47a6e356ae9f9bbece3df3c4b6e083bde2a955fe583e79071c05e8348280104")
	require.NoError(t, err)
	dsessionAT1Gamma, err := hex.DecodeString("96515ab6b675874566529d859a131b50")
	require.NoError(t, err)
	dsessionAT1Delta, err := hex.DecodeString("b05bebaa197fe1920b42d1eff6fecc4aac538ab23f58f17b80d131cdb5e112c53c3bd6e4f0cf2df35f1e7d668b2ad1df")
	require.NoError(t, err)
	dsessionAT2, err := hex.DecodeString("f1872b8c7d23cc9702b4b118d5bb60bfc25f5c54c177fd7929c4f5af0a68eae5")
	require.NoError(t, err)
	dsessionAT3, err := hex.DecodeString("74d2fe513e03e8fbe44385164e964f536e0c32c6af07ba2a71596a1fec33a711")
	require.NoError(t, err)
	dsessionBT1, err := hex.DecodeString("913b88079eab1350bf1bb9f8733dc001f32cf5438448c0adaa79d20537a9964eabfea79fc55ef3557b3e39fe01613b2d789e01d26a018d02e2388603a734110e478699d7e90292a393909009975889be1719aff29edbf6a3ec170589689840cf615fff22aa1b37abb9d9ba010953ee154c78f9e0eee28d625a7d2df73b5aa22b502b5040edb7fe8feb48b13541fb647974a3e5d24441e9021da8ad37fefeca053bfeccc3e28e9e9bc334ea418a31a2bbbd2a144eb045a30f91c3bd6cb39f82c703125f7620e44935f3ed76e540ca839980f208afa40d2773eb60b35ed8ac9a26")
	require.NoError(t, err)
	dsessionBT1Alpha, err := hex.DecodeString("913b88079eab1350bf1bb9f8733dc001f32cf5438448c0adaa79d20537a9964e")
	require.NoError(t, err)
	dsessionBT1Beta, err := hex.DecodeString("abfea79fc55ef3557b3e39fe01613b2d789e01d26a018d02e2388603a734110e478699d7e90292a393909009975889be1719aff29edbf6a3ec170589689840cf615fff22aa1b37abb9d9ba010953ee154c78f9e0eee28d625a7d2df73b5aa22b502b5040edb7fe8feb48b13541fb647974a3e5d24441e9021da8ad37fefeca05")
	require.NoError(t, err)
	dsessionBT1Gamma, err := hex.DecodeString("3bfeccc3e28e9e9bc334ea418a31a2bb")
	require.NoError(t, err)
	dsessionBT1Delta, err := hex.DecodeString("bd2a144eb045a30f91c3bd6cb39f82c703125f7620e44935f3ed76e540ca839980f208afa40d2773eb60b35ed8ac9a26")
	require.NoError(t, err)
	dsessionBT2, err := hex.DecodeString("12424018c8a15ca1d88247ef1285b3f8d36fffe33090a5af87b453acb2e7626e")
	require.NoError(t, err)
	dsessionBT3, err := hex.DecodeString("4e01f3a88fa886b41f786dab1ccf82f94a73082bbb8444c0408b875187355b9a")
	require.NoError(t, err)

	dsessionDhSeedA, err := hex.DecodeString("324d226178bc2e0f625dcb91d83cb7fd8ed710755695559927fc75edff85a96b")
	require.NoError(t, err)
	dsessionDhSeedB, err := hex.DecodeString("79455c612276de0d2d511744936efc30c4cbb0e9715b737dbaca8d7d4acaf8b0")
	require.NoError(t, err)

	dsessionCtidhSeedSkA, err := hex.DecodeString("0200fd0000ff01fffe00fe000100fe00000001fefe00010000fd0001000000fd0000fe00ff0200fffdff010000ff000201ff00fe0100ff000000010000ff030000010100020101ff0002ff00ff0001000002000002ff0101ff010000ff01020100000000fe0000ff000100ff00ff000100ff000000ff000001ff02ff010000000100")
	require.NoError(t, err)
	dsessionCtidhSeedPkA, err := hex.DecodeString("45a65c2972ddf00acf524db29bf9394ce79a17fdb08f1f135dd8b3296d4d83281381b039312a8fbb19a982bea2f55b71e7998c125aeea20eebbbd683b556f35bf250c0b07c7b59251b36610110aa506ddeb8400df688f2560fc9ab8c830786acd47a6e356ae9f9bbece3df3c4b6e083bde2a955fe583e79071c05e8348280104")
	require.NoError(t, err)

	dsessionCtidhSeedSkB, err := hex.DecodeString("01ff00fffd0100000004ff040000000002020100ff0002ff000000020001fd0000ff00ff010301000103000000000000fe03ff0000ffffff02010000ff00fd01010002ff00fe010100ff01ffffff00ff0100010100030100000000000100fc00fe00000001fe0000010000ff000200010100000000000200fe01ff00ff0001000000")
	require.NoError(t, err)
	dsessionCtidhSeedPkB, err := hex.DecodeString("abfea79fc55ef3557b3e39fe01613b2d789e01d26a018d02e2388603a734110e478699d7e90292a393909009975889be1719aff29edbf6a3ec170589689840cf615fff22aa1b37abb9d9ba010953ee154c78f9e0eee28d625a7d2df73b5aa22b502b5040edb7fe8feb48b13541fb647974a3e5d24441e9021da8ad37fefeca05")
	require.NoError(t, err)

	dSessionPassphrase := []byte("reunion is for rendezvous")

	createDeterministicSesson := func(passphrase, payload, seed []byte) *Session {
		var ctidhPubKey *[csidhPubKeyLen]byte
		var ctidhPrivKey *[csidhPrivKeyLen]byte
		var dhSeed *[32]byte
		var gammaSeed []byte
		var deltaSeed []byte
		var dummySeed []byte
		var tweak uint8

		if hmac.Equal(seed, dsessionSeedA) {
			dhSeed = &[32]byte{}
			copy(dhSeed[:], dsessionDhSeedA)

			ctidhPubKey = &[csidhPubKeyLen]byte{}
			copy(ctidhPubKey[:], dsessionCtidhSeedPkA)
			ctidhPrivKey = &[csidhPrivKeyLen]byte{}
			copy(ctidhPrivKey[:], dsessionCtidhSeedSkA)

			gammaSeed = dsessionGammaSeedA
			deltaSeed = dsessionDeltaSeedA
			dummySeed = dsessionDummySeedA
			tweak = dsessionTweakA
		} else if hmac.Equal(seed, dsessionSeedB) {
			dhSeed = &[32]byte{}
			copy(dhSeed[:], dsessionDhSeedB)

			ctidhPubKey = &[csidhPubKeyLen]byte{}
			copy(ctidhPubKey[:], dsessionCtidhSeedPkB)
			ctidhPrivKey = &[csidhPrivKeyLen]byte{}
			copy(ctidhPrivKey[:], dsessionCtidhSeedSkB)

			gammaSeed = dsessionGammaSeedB
			deltaSeed = dsessionDeltaSeedB
			dummySeed = dsessionDummySeedB
			tweak = dsessionTweakB
		} else {
			panic("wrong seed")
		}

		salt := &[32]byte{}
		copy(salt[:], DefaultHkdfSalt)

		return CreateSession(salt, passphrase, payload, dhSeed, ctidhPubKey, ctidhPrivKey, gammaSeed[:], deltaSeed[:], dummySeed[:], tweak)
	}

	t.Logf("Alice starting deterministic session with:\n")
	t.Logf("dSessionPassphrase: %s", dSessionPassphrase)
	t.Logf("dsessionPayloadA: %x", dsessionPayloadA)
	t.Logf("dsessionSeedA: %x", dsessionSeedA)

	alice := createDeterministicSesson(dSessionPassphrase, dsessionPayloadA, dsessionSeedA)

	t.Logf("Bob starting deterministic session with:\n")
	t.Logf("dSessionPassphrase: %s", dSessionPassphrase)
	t.Logf("dsessionPayloadA: %x", dsessionPayloadB)
	t.Logf("dsessionSeedA: %x", dsessionSeedB)

	bob := createDeterministicSesson(dSessionPassphrase, dsessionPayloadB, dsessionSeedB)

	t.Logf("Alice pdk: %x", alice.Pdk[:])
	t.Logf("Bob pdk: %x", bob.Pdk[:])

	// self.AT2 = A.process_t1(B.t1)
	bobT1Blob, err := bob.T1.MarshalBinary()
	require.NoError(t, err)
	aT2, err := alice.ProcessT1(bobT1Blob)
	require.NoError(t, err)

	// self.BT2 = B.process_t1(A.t1)
	aliceT1Blob, err := alice.T1.MarshalBinary()
	require.NoError(t, err)
	bT2, err := bob.ProcessT1(aliceT1Blob)
	require.NoError(t, err)

	// self.AT3, a_isdummy = A.process_t2(B.t1.id, self.BT2)
	bT1Id := bob.T1.ID()
	aT3, aIsDummy := alice.ProcessT2(&bT1Id, bT2)

	// self.BT3, b_isdummy = B.process_t2(A.t1.id, self.AT2)
	aT1Id := alice.T1.ID()
	bT3, bIsDummy := bob.ProcessT2(&aT1Id, aT2)

	require.Equal(t, alice.T1.Alpha[:], dsessionAT1Alpha)
	require.Equal(t, alice.T1.Beta[:], dsessionAT1Beta)
	require.Equal(t, alice.T1.Gamma[:], dsessionAT1Gamma)
	require.Equal(t, alice.T1.Delta[:], dsessionAT1Delta)
	require.Equal(t, aliceT1Blob, dsessionAT1)

	// assert not a_isdummy and not b_isdummy
	require.False(t, aIsDummy)
	require.False(t, bIsDummy)

	// A.process_t3(B.t1.id, self.BT3)
	// B.process_t3(A.t1.id, self.AT3)
	alice.ProcessT3(&bT1Id, bT3)
	bob.ProcessT3(&aT1Id, aT3)

	require.Equal(t, aT2, dsessionAT2)
	require.Equal(t, aT3, dsessionAT3)

	require.Equal(t, bobT1Blob, dsessionBT1[:])
	require.Equal(t, bob.T1.Alpha[:], dsessionBT1Alpha)
	require.Equal(t, bob.T1.Beta[:], dsessionBT1Beta)
	require.Equal(t, bob.T1.Gamma[:], dsessionBT1Gamma)
	require.Equal(t, bob.T1.Delta[:], dsessionBT1Delta)

	require.Equal(t, bT2, dsessionBT2)
	require.Equal(t, bT3, dsessionBT3)
}
