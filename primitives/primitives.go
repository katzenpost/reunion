// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package primitives

//#include "monocypher.h"
import "C"
import (
	"crypto/aes"
	"encoding/binary"
	"hash"
	"unsafe"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

func Hash(b []byte) *[32]byte {
	out := blake2b.Sum512(b)
	ret := [32]byte{}
	copy(ret[:], out[:32])
	return &ret
}

func Argon2(password []byte, salt *[32]byte) []byte {
	return argon2.Key(password, salt[:], 3, 100000, 1, 32)
}

type HKDF struct {
	PRK []byte
}

func (h *HKDF) Hash() hash.Hash {
	h1, err := blake2b.New512(nil)
	if err != nil {
		panic(err)
	}
	return h1
}

func NewHKDF(ikm []byte, salt *[32]byte) *HKDF {
	h := &HKDF{}
	h.PRK = hkdf.Extract(h.Hash, ikm, salt[:])
	return h
}

func (h *HKDF) Expand(info []byte, length int) []byte {
	r := hkdf.Expand(h.Hash, h.PRK, info)
	out := make([]byte, length)
	count, err := r.Read(out)
	if err != nil {
		panic(err)
	}
	if count != length {
		panic("hkdf expand failure")
	}
	return out
}

const KeySize = 32

func AeadEcbEncrypt(key, mesg *[KeySize]byte) *[KeySize]byte {
	cipher, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	encrypted := &[KeySize]byte{}
	size := 16
	for bs, be := 0, size; bs < KeySize; bs, be = bs+size, be+size {
		cipher.Encrypt(encrypted[bs:be], mesg[bs:be])
	}
	return encrypted
}

func AeadEcbDecrypt(key, mesg *[KeySize]byte) *[KeySize]byte {
	cipher, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	decrypted := &[KeySize]byte{}
	size := 16
	for bs, be := 0, size; bs < KeySize; bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], mesg[bs:be])
	}
	return decrypted
}

const aeadMacSize = 16

func AeadEncrypt(key, mesg, ad []byte) []byte {
	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, cipher.NonceSize())
	out := cipher.Seal(nil, nonce, mesg, ad)
	ciphertext, tag := out[:len(mesg)], out[len(mesg):]
	return append(tag, ciphertext...)
}

func AeadDecrypt(key, ct, ad []byte) ([]byte, bool) {
	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		panic(err)
	}
	tag, ciphertext := ct[:cipher.Overhead()], ct[cipher.Overhead():]
	ct2 := append(ciphertext, tag...)
	nonce := make([]byte, cipher.NonceSize())
	ret, err := cipher.Open(nil, nonce, ct2, ad)
	if err != nil {
		return nil, false
	}
	return ret, true
}

func Unelligator(hidden *[KeySize]byte) *[32]byte {
	curve := &[KeySize]byte{}
	C.crypto_elligator_map((*C.uint8_t)(unsafe.Pointer(&curve[0])), (*C.uint8_t)(unsafe.Pointer(&hidden[0])))
	return curve
}

func GenerateHiddenKeyPair(seed *[KeySize]byte) (*[KeySize]byte, *[KeySize]byte) {
	pkraw := make([]byte, KeySize)
	skraw := make([]byte, KeySize)
	C.crypto_elligator_key_pair((*C.uint8_t)(unsafe.Pointer(&pkraw[0])),
		(*C.uint8_t)(unsafe.Pointer(&skraw[0])),
		(*C.uint8_t)(unsafe.Pointer(&seed[0])))
	pk := &[32]byte{}
	copy(pk[:], pkraw)
	sk := &[32]byte{}
	copy(sk[:], skraw)
	return pk, sk
}

func HighCtidhDeterministicRNG(seed []byte) func(buf []byte, context uint64) {
	if len(seed) < 32 {
		panic("deterministic seed should be at least 256 bits")
	}

	contextState := make(map[uint64]uint64)

	shake256CSPRNG := func(buf []byte, context uint64) {
		// Update the context state
		contextState[context]++
		portableState := make([]byte, 8)
		portableContext := make([]byte, 8)
		binary.LittleEndian.PutUint64(portableState, contextState[context])
		binary.LittleEndian.PutUint64(portableContext, context)

		// Create SHAKE-256 hash instance
		shake := sha3.NewShake256()
		shake.Write(portableContext)
		shake.Write(portableState)
		shake.Write(seed)

		// Generate output
		output := make([]byte, len(buf))
		shake.Read(output)

		// Convert to little-endian uint32 and pack to native byte order
		for i := 0; i < len(buf); i += 4 {
			portableUint32 := binary.LittleEndian.Uint32(output[i : i+4])
			binary.LittleEndian.PutUint32(buf[i:i+4], portableUint32)
		}
	}

	return shake256CSPRNG
}
