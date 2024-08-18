// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package primitives

import (
	"testing"
	"encoding/hex"

	"github.com/stretchr/testify/require"
)


func TestPrimitivesWithVectors(t *testing.T) {
	// Hash vectors missing in the python ref implemention
	expectedOut, err := hex.DecodeString("4d15588c33aa290cbcb755ac9ff8ee1fa33fd56d8b47f1c050cf9b9bc59cc201")
	require.NoError(t, err)
	in, err := hex.DecodeString("638ef9d8d8bfff8ad0bd7d9031bcc91ec2897419ac0714195a2aa31a9f9c6b14")
	require.NoError(t, err)
	out := Hash(in)
	require.Equal(t, out[:], expectedOut)


/* test vectors from ref python
prp_key = bytes.fromhex('37620a87ccc74b5e425164371603bd96c794594b7d07e4887bae6c7f08fa9659')
prp_msg = bytes.fromhex('5245554e494f4e20697320666f722052656e64657a766f75732e2e2e20505250')
prp_ct = bytes.fromhex('a74b26c607e56b1f59a84d91ff738e6b55f94ceedc418118347c2b733e5ebe92')
*/

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
