// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package reunion

import (
	"golang.org/x/crypto/sha3"

	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/reunion/primitives"
)

const (
	// sizes of CTIDH-1024 public and private keys
	csidhPubKeyLen  = 128
	csidhPrivKeyLen = 130

	AlphaLen = 32
	BetaLen  = csidhPubKeyLen
	gammaLen = 16
	deltaLen = 3500

	PayloadSize      = deltaLen
	Type1MessageSize = AlphaLen + BetaLen + gammaLen + deltaLen
	Type2MessageSize = 32
	Type3MessageSize = 32
)

// T1 is the first protocol message that contains the message to be sent as
// well as relevant cryptographic information.
// T1 message that consists of an Alpha, Beta, Gamma, and Delta items as bytes.
// Alpha contains a 32 byte X25519 public key encoded with Elligator.
// Beta contains a 128 byte CTIDH1024 public key.
// Gamma contains a 16 byte MAC.
// Delta contains a 3500 AEAD encrypted payload message.
type T1 struct {
	Alpha [AlphaLen]byte // X25519 pub key
	Beta  [BetaLen]byte  // CTIDH 1024 pub key
	Gamma [gammaLen]byte // MAC
	Delta []byte         // ciphertext
}

// ID returns a cryptographic hash of a T1 to uniquely identify Peers in the
// REUNION protocol run on a per epoch basis.
func (t *T1) ID() [32]byte {
	blob, err := t.MarshalBinary()
	if err != nil {
		panic(err)
	}
	id := primitives.Hash(blob)
	return *id
}

// Returns a serialization of all T1 fields as bytes.
func (t *T1) MarshalBinary() (data []byte, err error) {
	out := []byte{}
	out = append(out, t.Alpha[:]...)
	out = append(out, t.Beta[:]...)
	out = append(out, t.Gamma[:]...)
	out = append(out, t.Delta...)
	return out, nil
}

// Populate a T1's fields from serialized byte data.
func (t *T1) UnmarshalBinary(data []byte) error {
	copy(t.Alpha[:], data[:AlphaLen])
	copy(t.Beta[:], data[AlphaLen:AlphaLen+BetaLen])
	copy(t.Gamma[:], data[AlphaLen+BetaLen:AlphaLen+BetaLen+gammaLen])
	t.Delta = make([]byte, len(data[AlphaLen+BetaLen+gammaLen:]))
	copy(t.Delta[:], data[AlphaLen+BetaLen+gammaLen:])
	return nil
}

// Peer state structure including REUNION protocol messages as well as public
// and respective private key data.
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
	T3KeyRx  *[32]byte
	T3KeyTx  *[32]byte
	Payload  []byte
}

// Create a new Peer and store their T1 and Session in a Peer structure.
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

	csidhSs := s.DeriveSecret(sessionCsidhSk, csidhPk)
	shakeHash := make([]byte, len(csidhSs))
	sha3.ShakeSum256(shakeHash, csidhSs)
	p.CsidhSs = shakeHash

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

// ProcessT2 implements the inside of the for loop in Phase 3 of
// Algorithm 1. It returns a 2-tuple of (t3, is_dummy).
func (p *Peer) ProcessT2(t2 []byte) ([]byte, bool) {

	// Step 26: skBiγ ← rijndael-dec(T2kirx, T2Bi)
	// sk_gamma = prp_decrypt(peer.t2key_rx, t2)
	t2Ar := &[32]byte{}
	copy(t2Ar[:], t2)
	skGamma := primitives.AeadEcbDecrypt(p.T2KeyRx, t2Ar)

	// Step 27: if “” = aead-dec(sk B i γ , T 1 B i γ , RS) then
	// aead_res = aead_decrypt(sk_gamma, peer.t1.gamma, peer.session.salt)
	_, ok := primitives.AeadDecrypt(skGamma[:], p.T1.Gamma[:], p.Session.Salt[:])
	if ok {
		// Step 28: T3kitx ← H(T2kitx, T2Ai , T2Bi).
		// t3key_tx = Hash(peer.t2key_tx + peer.t2_tx + t2)
		p.T2Rx = t2
		t3KeyTx := primitives.Hash(append(p.T2KeyTx[:], append(p.T2Tx, t2...)...))

		// Step 29: T3kirx ← H(T2kirx, T2Bi, T2Ai)
		// peer.t3_key_rx = Hash(peer.t2key_rx + peer.t2_rx + peer.t2_tx)
		p.T3KeyRx = primitives.Hash(append(p.T2KeyRx[:], append(p.T2Rx, p.T2Tx...)...))

		// Step 30: T3Ai ← rijndael-enc(T3kitx, skAδ)
		// return prp_encrypt(t3key_tx, peer.session.sk_delta), False
		block := &[32]byte{}
		copy(block[:], p.Session.SkDelta)
		out := primitives.AeadEcbEncrypt(t3KeyTx, block)
		return out[:], false
	}
	// Step 31: else
	// Step 32: T3Ai ← H(RNG(32))
	t1id := p.T1.ID()
	return p.Session.DummyHKDF.Expand(append(t1id[:], t2...), 32), true
}

// ProcessT3 implements Phase 4 of Algorithm 1. It returns nil or the Peer's
// payload as bytes.
func (p *Peer) ProcessT3(t3 []byte) []byte {
	// Step 36: for each new T3Bi do ▷ Phase 4: Process T3; decrypt δ
	if p.T2Rx == nil {
		return nil
	}

	// Step 37: skBiδ ← rijndael-dec(T3kirx, T3Bi).
	t3Ar := &[32]byte{}
	copy(t3Ar[:], t3)
	skDelta := primitives.AeadEcbDecrypt(p.T3KeyRx, t3Ar)

	// Step 38: if msgBi ← aead-dec(skBiδ, T1Biδ, RS) then
	var ok bool
	p.Payload, ok = primitives.AeadDecrypt(skDelta[:], p.T1.Delta, p.Session.Salt[:])
	if ok {
		p.Session.Results = append(p.Session.Results, p.Payload)
	}
	return p.Payload
}

// Session structure for storing state about a session including Peer states,
// various protocol parameters, as well as public and respective private key
// data.
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
	DummyHKDF *primitives.HKDF
}

// Create and populate a Session structure for a protocol run within one
// epoch.
func CreateSession(
	salt *[32]byte,
	passphrase,
	payload []byte,
	dhSeed *[32]byte,
	ctidhPubKey *[csidhPubKeyLen]byte,
	ctidhPrivKey *[csidhPrivKeyLen]byte,
	gammaSeed,
	deltaSeed,
	dummySeed []byte, tweak byte) *Session {

	dhEpk, dhSk := primitives.GenerateHiddenKeyPair(dhSeed)
	kdf := primitives.NewHKDF(primitives.Argon2(passphrase, salt), salt)
	pdkRaw := kdf.Expand([]byte(""), 32)
	pdk := &[32]byte{}
	copy(pdk[:], pdkRaw)

	skGamma := primitives.Hash(append(pdk[:], append(gammaSeed, payload...)...))
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

	dummyHkdf := primitives.NewHKDF(dummySeed, salt)

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
		DummyHKDF: dummyHkdf,
	}
}

// Process a Peer's T1 protocol message by deserializing and creating or
// updating a respective Peer structure based on a cryptographic hash of the T1
// message.
func (s *Session) ProcessT1(t1Bytes []byte) ([]byte, error) {
	t1 := new(T1)
	err := t1.UnmarshalBinary(t1Bytes)
	if err != nil {
		return nil, err
	}
	peer, ok := s.Peers[t1.ID()]
	if !ok {
		peer, err = NewPeer(t1, s)
		s.Peers[t1.ID()] = peer
		if err != nil {
			return nil, err
		}
	}
	return peer.T2Tx, nil
}

// Process a Peer's T2 protocol message which is a response to a T1 and in turn
// generates a T3. The T3 may be a true T3 that is encoded with Elligator to be
// indistinguishable from a uniformly random bit string or a dummy T3 that is
// also indistinguishable from a uniformly random bit string.
func (s *Session) ProcessT2(t1id *[32]byte, t2 []byte) ([]byte, bool) {
	peer, ok := s.Peers[*t1id]
	if ok {
		return peer.ProcessT2(t2)
	}
	return s.DummyHKDF.Expand(append(t1id[:], t2...), 32), true
}

// ProcessT3 returns a byte slice on success or a nil on failure.
func (s *Session) ProcessT3(t1id *[32]byte, t3 []byte) []byte {
	peer, ok := s.Peers[*t1id]
	if ok {
		return peer.ProcessT3(t3)
	}
	return nil
}
