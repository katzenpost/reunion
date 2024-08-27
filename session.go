// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package reunion

import (
// "github.com/katzenpost/hpqc/nike/ctidh/ctidh1024"
// "github.com/katzenpost/hpqc/nike/x25519"
)

const (
	alphaLen = 32
	betaLen  = 128
	gammaLen = 16
)

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
