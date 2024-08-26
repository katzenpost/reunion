// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package reunion

import (
// "github.com/katzenpost/hpqc/nike/ctidh/ctidh1024"
// "github.com/katzenpost/hpqc/nike/x25519"
)

type T1 struct {
	Alpha [32]byte  // X25519 pub key
	Beta  [128]byte // CTIDH 1024 pub key
	Gamme [16]byte  // MAC
	Delta []byte    // ciphertext
}
