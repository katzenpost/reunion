// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package primitives

//#include "monocypher.h"
import "C"
import (
	"unsafe"
	"crypto/aes"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"

	hpqchash "github.com/katzenpost/hpqc/hash"
)

func Hash(b []byte) [32]byte {
	return hpqchash.Sum256(b)
}


// TODO argon2i
/*
def argon2i(password: bytes, salt: bytes, _wipe: bool=False):
    return monocypher.argon2i_32(
        nb_blocks=100000,
        nb_iterations=3,
        password=password,
        salt=salt,
        key=None,
        ad=None,
        _wipe=_wipe,
    )
*/


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
	nonce := make([]byte, 24)	
	mac, ciphertext, _ := AeadLock(mesg, nonce, key, ad)
	return append(mac, ciphertext...)
}

func AeadDecrypt(key, mesg, ad []byte) []byte {
	nonce := make([]byte, 32)
	mac := mesg[:aeadMacSize]
	ct := mesg[aeadMacSize:]
	return AeadUnlock(ct, nonce, key, mac, ad)
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
