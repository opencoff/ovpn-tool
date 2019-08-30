// cipher.go - encrypt/decrypt routines for DB data

//
// (c) 2018 Sudhi Herle; License GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package pki

// Internal details:
// * We use AES-256-GCM for encrypting all data
// * AES key is derived from the db password +
//   random 32 byte salt via kdf.
// * We use hash of the salt as the nonce for AEAD (GCM)
// * We always store salt + encrypted_bytes
// * The first 32 bytes of data we read from the DB is always
//   the salt.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/argon2"
)

const (
	_Time    uint32 = 1
	_Mem     uint32 = 1 * 1024 * 1024
	_Threads uint8  = 8
)

// Argon2 KDF
func kdf(pwd []byte, salt []byte) []byte {
	// Generate a 32-byte AES-256 key
	return argon2.IDKey(pwd, salt, _Time, _Mem, _Threads, 32)
}

// expand a user password string and derive a 32 byte key
func kdfstr(pw string, salt []byte) []byte {
	h := sha512.New()
	h.Write([]byte(pw))
	pwd := h.Sum(nil)
	return kdf(pwd, salt)
}

// entangle an expanded password with a DB key
func (d *database) key(cn string) []byte {
	m := hmac.New(sha256.New, d.pwd)
	m.Write([]byte(cn))
	return m.Sum(nil)
}

// encrypt a blob and return it
func (d *database) encrypt(b []byte) ([]byte, error) {
	var salt [32]byte

	n, err := rand.Read(salt[:])
	if err != nil || n != 32 {
		panic("can't read 32 rand bytes")
	}

	h := sha256.New()
	h.Write(salt[:])
	nonce := h.Sum(nil)

	key := kdf(d.pwd, salt[:])

	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ae, err := cipher.NewGCMWithNonceSize(aes, len(nonce))
	if err != nil {
		return nil, err
	}

	c := ae.Seal(nil, nonce, b, salt[:])
	c = append(c, salt[:]...)

	return c, nil
}

// decrypt a buffer and return
func (d *database) decrypt(b []byte) ([]byte, error) {
	// 32: Salt size (suffix)
	// 16: GCM tag size
	if len(b) < (32 + 16) {
		return nil, ErrTooSmall
	}

	n := len(b)
	salt := b[n-32:]
	b = b[:n-32]

	h := sha256.New()
	h.Write(salt[:])
	nonce := h.Sum(nil)

	key := kdf(d.pwd, salt)

	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ae, err := cipher.NewGCMWithNonceSize(aes, len(nonce))
	if err != nil {
		return nil, err
	}

	c, err := ae.Open(nil, nonce, b, salt)
	if err != nil {
		return nil, err
	}

	return c, nil
}
