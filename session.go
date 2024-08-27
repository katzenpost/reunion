// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package reunion

import (
	"github.com/katzenpost/hpqc/nike/schemes"
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

func (t *T1) ID() [32]byte {
	blob, err := t.MarshalBinary()
	if err != nil {
		panic(err)
	}
	id := primitives.Hash(blob)
	return *id
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

type Peer struct {
	T1       *T1
	Session  *Session
	AlphaKey *[32]byte
	DhPk     *[32]byte
	CsidhPk  *[32]byte
	DhSs     *[32]byte
	CsidhSs  []byte
	T2KeyTx  *[32]byte
	T2KeyRx  *[32]byte
	T2Tx     []byte
	T2Rx     []byte
	Payload  []byte
}

func NewPeer(t1 *T1, session *Session) (*Peer, error) {
	p := &Peer{}
	p.T1 = t1
	p.Session = session

	// Step 15: pdkBi ← H(pdk, T1Biβ, T1Biγ, T1Biδ)
	p.AlphaKey = primitives.Hash(append(session.Pdk[:], append(t1.Beta[:], append(t1.Gamma[:], t1.Delta...)...)...))

	// Step 16: epkBiα ← unelligator(rijndael-dec(pdkBi , T1Biα )).
	p.DhPk = primitives.Unelligator(primitives.AeadEcbDecrypt(p.AlphaKey, &t1.Alpha))

	// Step 17: epkBiβ ← T1Biβ
	s := schemes.ByName("CTIDH1024")
	p.CsidhPk = &[32]byte{}
	copy(p.CsidhPk[:], t1.Beta[:])

	csidhPk, err := s.UnmarshalBinaryPublicKey(t1.Beta[:])
	if err != nil {
		return nil, err
	}

	// Step 18: dh1ssi ← H(DH(eskAα , epkBiα))
	// peer.dh_ss = x25519(session.dh_sk, peer.dh_pk)
	x := schemes.ByName("X25519")
	priv, err := x.UnmarshalBinaryPrivateKey(session.DhSk[:])
	if err != nil {
		return nil, err
	}
	pub, err := x.UnmarshalBinaryPublicKey(p.DhPk[:])
	if err != nil {
		return nil, err
	}
	ss := x.DeriveSecret(priv, pub)
	ssAr := &[32]byte{}
	copy(ssAr[:], ss)
	p.DhSs = ssAr

	// Step 19: dh2ssi ← H(DH(eskAβ , epkBiβ)).
	sessionCsidhSk, err := s.UnmarshalBinaryPrivateKey(session.CsidhSk[:])
	if err != nil {
		return nil, err
	}
	p.CsidhSs = s.DeriveSecret(sessionCsidhSk, csidhPk)

	// Step 20: T2kitx ← H(pdkA, pdkBi, dh1ssi, dh2ssi)
	p.T2KeyTx = primitives.Hash(append(session.AlphaKey[:], append(p.AlphaKey[:], append(p.DhSs[:], p.CsidhSs[:]...)...)...))

	// Step 21: T2kirx ← H(pdkBi, pdkA, dh1ssi, dh2ssi)
	p.T2KeyRx = primitives.Hash(append(p.AlphaKey[:], append(session.AlphaKey[:], append(p.DhSs[:], p.CsidhSs[:]...)...)...))

	// Step 22: T2Ai ← rijndael-enc(T2kitx, skAγ)
	t2TxAr := primitives.AeadEcbEncrypt(p.T2KeyTx, session.SkGamma)
	p.T2Tx = t2TxAr[:]
	p.T2Rx = nil
	p.Payload = nil

	return p, nil
}

type Session struct {
	Peers     map[[32]byte]*Peer
	Results   [][]byte
	DhEpk     *[32]byte
	DhSk      *[32]byte
	CsidhPk   *[csidhPubKeyLen]byte
	CsidhSk   *[csidhPrivKeyLen]byte
	Salt      *[32]byte
	Pdk       *[32]byte
	SkGamma   *[32]byte
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
	copy(alpha[:], alphaRaw[:])

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
		SkGamma:   skGamma,
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

func (s *Session) ProcessT1(t1Bytes []byte) ([]byte, error) {
	t1 := new(T1)
	err := t1.UnmarshalBinary(t1Bytes)
	if err != nil {
		return nil, err
	}
	peer, ok := s.Peers[t1.ID()]
	if !ok {
		peer, err = NewPeer(t1, s)
		if err != nil {
			return nil, err
		}
	}
	return peer.T2Tx, nil
}

func (s *Session) ProcessT2(t1id *[32]byte, t2 []byte) ([]byte, bool) {
	/*
		peer, ok := s.Peers[*t1id]
		if ok {
			//return peer.ProcessT2(t2)
		}
		// return s.DummyHKDF
	*/
	return nil, false // XXX

}
