// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package primitives

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/schemes"
)

// ALL the test vectors here are from the python ref.

func TestHash(t *testing.T) {
	// blake2b
	hashIn := []byte("REUNION is for rendezvous")
	expectedHashOut, err := hex.DecodeString("1ffb4f05cb3e841d44079afbcc51f62edbd7092294edac59846b8519f48c5a45")
	require.NoError(t, err)
	hashOut := Hash(hashIn)
	t.Logf("hashOut %x", hashOut)
	require.Equal(t, hashOut[:], expectedHashOut[:])
}

func TestPRP(t *testing.T) {

	key, err := hex.DecodeString("37620a87ccc74b5e425164371603bd96c794594b7d07e4887bae6c7f08fa9659")
	require.NoError(t, err)

	mesg, err := hex.DecodeString("5245554e494f4e20697320666f722052656e64657a766f75732e2e2e20505250")
	require.NoError(t, err)

	expectedCiphertext, err := hex.DecodeString("a74b26c607e56b1f59a84d91ff738e6b55f94ceedc418118347c2b733e5ebe92")
	require.NoError(t, err)

	keyArr := &[32]byte{}
	copy(keyArr[:], key)
	mesgArr := &[32]byte{}
	copy(mesgArr[:], mesg)

	ciphertext := AeadEcbEncrypt(keyArr, mesgArr)
	require.Equal(t, ciphertext[:], expectedCiphertext[:])

	block := &[32]byte{}
	copy(block[:], ciphertext)
	plaintext := AeadEcbDecrypt(keyArr, block)
	require.Equal(t, plaintext[:], mesg[:])
}

func TestAEAD(t *testing.T) {
	aeadKey, err := hex.DecodeString("2e845d6aa49d50fd388c9c7072aac817ec71e323a4d32532263a757c98404c8a")
	require.NoError(t, err)
	aeadMesg, err := hex.DecodeString("5245554e494f4e20697320666f722052656e64657a766f7573")
	require.NoError(t, err)
	aeadAd, err := hex.DecodeString("e7bab55e065f23a4cb74ce9e6c02aed0c31c90cce16b3d6ec7c98a3ed65327cf")
	require.NoError(t, err)
	aeadCt, err := hex.DecodeString("a405c2d42d576140108a84a08a9c8ee140d5c72c5332ec6713cf7c6fb27719a9007606f7834853245b")
	require.NoError(t, err)

	actualCt := AeadEncrypt(aeadKey, aeadMesg, aeadAd)
	require.Equal(t, actualCt, aeadCt)

	aeadDecrypted := AeadDecrypt(aeadKey, actualCt, aeadAd)
	require.Equal(t, aeadDecrypted, aeadMesg)
}

func TestElligator(t *testing.T) {
	seedA := &[KeySize]byte{}
	rawSeedA, err := hex.DecodeString("e60498784e625a21d6285ee7a6144a0464dab10120b11f3794dd00e36da98c27")
	require.NoError(t, err)
	copy(seedA[:], rawSeedA)
	rawPkA, err := hex.DecodeString("b92b89f7bea9d4deee61a07a930edc4f50a7e5eb38a6b5667f44dea5032703f5")
	require.NoError(t, err)
	rawSkA, err := hex.DecodeString("f988f98f466ff8585598ad12956b385e6090e9fdfdac3ca17c77cad61ac8a430")
	require.NoError(t, err)
	pkA, skA := GenerateHiddenKeyPair(seedA)
	require.Equal(t, pkA, rawPkA)
	require.Equal(t, skA, rawSkA)

	seedB := &[KeySize]byte{}
	rawSeedB, err := hex.DecodeString("f50a1248b83f07c6232485508bc889352531a5387b18580d8f6685c352c454d2")
	require.NoError(t, err)
	copy(seedB[:], rawSeedB)
	rawPkB, err := hex.DecodeString("9c1c114b9f11908e6f046805c97a1ba8261e3a3a34cfca9a72d20f3701c553b1")
	require.NoError(t, err)
	rawSkB, err := hex.DecodeString("8ba80391df517ee3e3901046adf8c4aab8068cb9a569349e98ee8241b7fde770")
	require.NoError(t, err)
	pkB, skB := GenerateHiddenKeyPair(seedB)
	require.Equal(t, pkB, rawPkB)
	require.Equal(t, skB, rawSkB)

	curveA := Unelligator(pkA)
	expectedCurveA, err := hex.DecodeString("95fa3b2a70e42f4dc66117a02680ddfe45a55451654e7bd685ba2a4179289104")
	require.NoError(t, err)
	require.Equal(t, expectedCurveA, curveA)

	curveB := Unelligator(pkB)
	expectedCurveB, err := hex.DecodeString("6d4d5132efddd1ccfdb42178d5cab993617b50a43e24a0b6679e0d6f17ddae1e")
	require.NoError(t, err)
	require.Equal(t, expectedCurveB, curveB)

	// test elligator DH
	s := schemes.ByName("X25519")
	pubKey1, err := s.UnmarshalBinaryPublicKey(curveB)
	require.NoError(t, err)

	pubKey2, err := s.UnmarshalBinaryPublicKey(curveA)
	require.NoError(t, err)

	privKeyA, err := s.UnmarshalBinaryPrivateKey(skA)
	require.NoError(t, err)

	privKeyB, err := s.UnmarshalBinaryPrivateKey(skB)
	require.NoError(t, err)

	ss1 := s.DeriveSecret(privKeyA, pubKey1)
	ss2 := s.DeriveSecret(privKeyB, pubKey2)
	require.Equal(t, ss1, ss2)
}

func TestArgon2i(t *testing.T) {
	argon2Password := []byte("REUNION is for rendezvous")
	argon2Salt := make([]byte, 32)
	argon2ExpectedResult, err := hex.DecodeString("131f782cae57faa5055277621aec7c3984fbef048c8d183848f3def2697c7acd")
	require.NoError(t, err)
	argon2Result := Argon2(argon2Password, argon2Salt)
	require.Equal(t, argon2Result, argon2ExpectedResult)
}

func TestHKDF(t *testing.T) {
	hkdfKey, err := hex.DecodeString("513e3c670ab00a436de0d801b07e085149ef205d27807d656253cd9a08a7bdf0")
	require.NoError(t, err)
	hkdfSalt := make([]byte, 32)
	hkdfExpected, err := hex.DecodeString("9a3b6d37987a9ea05709a9ef2b8c8e4e0b0c51088cb6edc93bcacf4ff36fda1c")
	require.NoError(t, err)
	hkdfOut := HKDF(hkdfKey, hkdfSalt)
	require.Equal(t, hkdfOut, hkdfExpected)
}
