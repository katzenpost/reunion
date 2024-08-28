// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package reunion

import (
	"bytes"
)

var (
	DefaultAeadNonce = bytes.Repeat([]byte{0x00}, 24)
	DefaultArgonSalt = bytes.Repeat([]byte{0x00}, 32)
	DefaultHkdfSalt  = bytes.Repeat([]byte{0x00}, 32)

	DefaultCtidhSize = 1024
)
