// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package reunion

import (
	// "github.com/katzenpost/hpqc/nike/ctidh/ctidh1024"
	// "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/reunion/primitives"
)

const (
	// sizes of CTIDH-1024 public and private keys
	csidhPubKeyLen  = 128
	csidhPrivKeyLen = 130

	alphaLen = 32
	betaLen  = csidhPubKeyLen
	gammaLen = 16
)

// DefaultHKDFSalt

type T1 struct {
	Alpha [alphaLen]byte // X25519 pub key
	Beta  [betaLen]byte  // CTIDH 1024 pub key
	Gamma [gammaLen]byte // MAC
	Delta []byte         // ciphertext
}

func (t *T1) MarshalBinary() (data []byte, err error) {
	out := []byte{}
	out = append(out, t.Alpha[:]...)
	out = append(out, t.Beta[:]...)
	out = append(out, t.Gamma[:]...)
	out = append(out, t.Delta...)
	return out, nil
}

func (t *T1) UnmarshalBinary(data []byte) error {
	copy(t.Alpha[:], data[:alphaLen])
	copy(t.Beta[:], data[alphaLen:alphaLen+betaLen])
	copy(t.Gamma[:], data[alphaLen+betaLen:alphaLen+betaLen+gammaLen])
	t.Delta = make([]byte, len(data[alphaLen+betaLen+gammaLen:]))
	copy(t.Delta[:], data[alphaLen+betaLen+gammaLen:])
	return nil
}

type Peer struct{}

type Session struct {
	Peers     map[[32]byte]*Peer
	Results   [][]byte
	DhEpk     *[32]byte
	DhSk      *[32]byte
	CsidhPk   *[csidhPubKeyLen]byte
	CsidhSk   *[csidhPrivKeyLen]byte
	Salt      *[32]byte
	Pdk       *[32]byte
	SkGamma   []byte
	SkDelta   []byte
	AlphaKey  *[32]byte
	T1        *T1
	DummyHKDF []byte
}

func CreateSession(
	salt *[32]byte,
	passphrase,
	payload []byte,
	dhSeed *[32]byte,
	ctidhPubKey *[csidhPubKeyLen]byte,
	ctidhPrivKey *[csidhPrivKeyLen]byte,
	gammeSeed,
	deltaSeed,
	dummySeed []byte, tweak byte) *Session {

	dhEpk, dhSk := primitives.GenerateHiddenKeyPair(dhSeed)
	pdk := primitives.HKDF(primitives.Argon2(passphrase, salt), salt)
	skGamma := primitives.Hash(append(pdk[:], append(gammeSeed, payload...)...))
	skDelta := primitives.Hash(append(pdk[:], append(deltaSeed, payload...)...))

	// t1 beta is the unencrypted csidh pk
	// beta = self.csidh_pk
	beta := ctidhPubKey

	// Step 6: T1Aγ ← aead-enc(sk Aγ ,“”, RS)
	// gamma = aead_encrypt(self.sk_gamma, b"", salt)
	gammaRaw := primitives.AeadEncrypt(skGamma[:], []byte(""), salt[:])

	// Step 7: T1Aδ ← aead-enc(sk Aδ , msg a , RS)
	// delta = aead_encrypt(self.sk_delta, payload, salt)
	delta := primitives.AeadEncrypt(skDelta[:], payload, salt[:])

	// Step 8: pdkA ← H(pdk, epkAβ , T1Aγ , T1Bδ )
	alphaKey := primitives.Hash(append(pdk[:], append(beta[:], append(gammaRaw, delta...)...)...))

	// Step 9: T1Aα ← rijndael-enc(pdkA , epkAα)
	// alpha = prp_encrypt(self.alpha_key, self.dh_epk)
	alphaRaw := primitives.AeadEcbEncrypt(alphaKey, dhEpk)
	alpha := &[32]byte{}
	copy(alpha[:], alphaRaw)

	gamma := &[16]byte{}
	copy(gamma[:], gammaRaw)

	// Step 10: T1A ← T1 Aα ∥ epkAβ ∥ T1 Aγ ∥ T1 Aδ
	// self.t1 = T1(alpha + beta + gamma + delta)
	t1 := &T1{
		Alpha: *alpha,
		Beta:  *beta,
		Gamma: *gamma,
		Delta: delta,
	}

	dummyHkdf := primitives.HKDF(dummySeed, salt)

	return &Session{
		Peers:     make(map[[32]byte]*Peer),
		Results:   make([][]byte, 0),
		DhEpk:     dhEpk,
		DhSk:      dhSk,
		CsidhPk:   ctidhPubKey,
		CsidhSk:   ctidhPrivKey,
		Salt:      salt,
		Pdk:       pdk,
		SkGamma:   skGamma[:],
		SkDelta:   skDelta[:],
		AlphaKey:  alphaKey,
		T1:        t1,
		DummyHKDF: dummyHkdf[:],
	}
}

func CreateDeterministicSesson(passphrase, payload, seed []byte, ctidhPubKey *[csidhPubKeyLen]byte, ctidhPrivKey *[csidhPrivKeyLen]byte) *Session {
	salt := &[32]byte{}
	copy(salt[:], DefaultHkdfSalt)
	dhSeed := primitives.Hash(append(seed, []byte("dh")...))
	gammaSeed := primitives.Hash(append(seed, []byte("g")...))
	deltaSeed := primitives.Hash(append(seed, []byte("d")...))
	dummySeed := primitives.Hash(append(seed, []byte("d")...))
	tweak := primitives.Hash(append(seed, []byte("t")...))[0]
	return CreateSession(salt, passphrase, payload, dhSeed, ctidhPubKey, ctidhPrivKey, gammaSeed[:], deltaSeed[:], dummySeed[:], tweak)
}
