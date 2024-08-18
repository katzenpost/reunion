// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package primitives

//#include "monocypher.h"
import "C"
import (
	"unsafe"
	"fmt"
	"crypto/aes"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/chacha20poly1305"
)

func Hash(b []byte) [32]byte {
	out := blake2b.Sum512(b)
	ret := [32]byte{}
	copy(ret[:], out[:32])
	return ret
}

func Argon2(password, salt []byte) []byte {
	return argon2.Key(password, salt, 3, 100000, 1, 32)
}

func HKDF(ikm, salt []byte) []byte {
	h := func() hash.Hash {
		h, err := blake2b.New256(nil)
		if err != nil {
			panic(err)
		}
		return h
	}
	return hkdf.Extract(h, ikm, salt)
}

const KeySize = 32


func AeadEcbEncrypt(key, mesg *[KeySize]byte) []byte {
	cipher, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	encrypted := make([]byte, KeySize)
	size := 16
	for bs, be := 0, size; bs < KeySize; bs, be = bs+size, be+size {
		cipher.Encrypt(encrypted[bs:be], mesg[bs:be])
	}
	return encrypted
}

func AeadEcbDecrypt(key, mesg *[KeySize]byte) []byte {
	cipher, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	decrypted := make([]byte, KeySize)
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
	fmt.Printf("\n\n AEAD NONCE SIZE %d\n\n", cipher.NonceSize())
	nonce := make([]byte, cipher.NonceSize())
	return cipher.Seal(nil, nonce, mesg, ad)
}

func AeadDecrypt(key, ct, ad []byte) []byte {
	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n\n AEAD NONCE SIZE %d\n\n", cipher.NonceSize())
	nonce := make([]byte, cipher.NonceSize())
	ret, err := cipher.Open(nil, nonce, ct, ad)
	if err != nil {
		panic(err)
	}
	return ret
}

func Unelligator(hidden []byte) []byte {
	curve := make([]byte, KeySize)
	C.crypto_elligator_map((*C.uint8_t)(unsafe.Pointer(&curve[0])), (*C.uint8_t)(unsafe.Pointer(&hidden[0])))
	return curve
}

func GenerateHiddenKeyPair(seed *[KeySize]byte) ([]byte, []byte) {
	pk := make([]byte, KeySize)
	sk := make([]byte, KeySize)
	C.crypto_elligator_key_pair((*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		(*C.uint8_t)(unsafe.Pointer(&seed[0])))
	return pk, sk
}
