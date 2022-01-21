package wcrypto

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/salsa20/salsa"
	"golang.org/x/crypto/twofish"
	"golang.org/x/crypto/xtea"
)

// NewBlowfishCipher new blowfish cipher
// The key argument should be the Blowfish key, from 1 to 56 bytes.
func NewBlowfishCipher(key []byte) (cipher.Block, error) { return blowfish.NewCipher(key) }

// NewCast5Cipher new cast5 cipher,
// The key size should 32
func NewCast5Cipher(key []byte) (cipher.Block, error) { return cast5.NewCipher(key) }

// NewTwofishCipher new twofish cipher
// The key argument should be the Twofish key, 16, 24 or 32 bytes.
func NewTwofishCipher(key []byte) (cipher.Block, error) { return twofish.NewCipher(key) }

// NewXteaCipher new xtea cipher
// The key argument should be the XTEA key.
// XTEA only supports 128 bit (16 byte) keys.
func NewXteaCipher(key []byte) (cipher.Block, error) { return xtea.NewCipher(key) }

// NewRc4Md5 new rc4-md5 key size should 16, iv size should one of 6,16
func NewRc4Md5(key, iv []byte) (cipher.Stream, error) {
	if k := len(key); k != 16 {
		return nil, KeySizeError(k)
	}
	if i := len(iv); i != 16 && i != 6 {
		return nil, IvSizeError(i)
	}
	h := md5.New()
	h.Write(key) // nolint: errcheck
	h.Write(iv)  // nolint: errcheck
	return rc4.NewCipher(h.Sum(nil))
}

// NewChacha20 new chacha20 key size should 32, iv size should one of 12,24
func NewChacha20(key, iv []byte) (cipher.Stream, error) {
	return chacha20.NewUnauthenticatedCipher(key, iv)
}

// NewSalsa20 new salsa20 key size should 32, iv size should one of 8
func NewSalsa20(key, iv []byte) (cipher.Stream, error) {
	if k := len(key); k != 32 {
		return nil, KeySizeError(k)
	}
	if i := len(iv); i != 8 {
		return nil, IvSizeError(i)
	}
	var c salsaStreamCipher
	copy(c.key[:], key)
	copy(c.nonce[:], iv)
	return &c, nil
}

type salsaStreamCipher struct {
	nonce   [8]byte
	key     [32]byte
	counter int
}

func (c *salsaStreamCipher) XORKeyStream(dst, src []byte) {
	var buf []byte
	padLen := c.counter % 64
	dataSize := len(src) + padLen
	if cap(dst) >= dataSize {
		buf = dst[:dataSize]
	} else {
		buf = make([]byte, dataSize)
	}

	var subNonce [16]byte
	copy(subNonce[:], c.nonce[:])
	binary.LittleEndian.PutUint64(subNonce[len(c.nonce):], uint64(c.counter/64))

	// It's difficult to avoid data copy here. src or dst maybe slice from
	// Conn.Read/Write, which can't have padding.
	copy(buf[padLen:], src)
	salsa.XORKeyStream(buf, buf, &subNonce, &c.key)
	copy(dst, buf[padLen:])

	c.counter += len(src)
}
