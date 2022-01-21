package wcrypto

import (
	"crypto/cipher"
)

type BlockMode string

const (
	BlockModeCBC BlockMode = "CBC"
	BlockModeCTR BlockMode = "CTR"
	BlockModeOFB BlockMode = "OFB"
	BlockModeCFB BlockMode = "CFB"
)

type encryptor func(b cipher.Block, iv []byte) cipher.Stream
type modeEncryptor struct {
	enc encryptor
	dec encryptor
}

var blockModes = map[BlockMode]modeEncryptor{
	BlockModeCBC: {NewCBCEncrypter, NewCBCDecrypter},
	BlockModeCTR: {cipher.NewCTR, cipher.NewCTR},
	BlockModeOFB: {cipher.NewOFB, cipher.NewOFB},
	BlockModeCFB: {cipher.NewCFBEncrypter, cipher.NewCFBDecrypter},
}

type Mode interface {
	Encrypt(block cipher.Block, data, iv []byte) ([]byte, error)
	Decrypt(block cipher.Block, data, iv []byte) ([]byte, error)
}

type mode struct {
	m modeEncryptor
}

func getModeByType(key BlockMode) Mode {
	m, ok := blockModes[key]
	if !ok {
		return nil
	}
	return &mode{m}
}

func (m *mode) Encrypt(block cipher.Block, data, iv []byte) ([]byte, error) {

	e := m.m.enc(block, iv)
	ciphertext := make([]byte, len(data))
	e.XORKeyStream(ciphertext, data)
	return ciphertext, nil
}

func (m *mode) Decrypt(block cipher.Block, data, iv []byte) ([]byte, error) {

	d := m.m.dec(block, iv)
	plaintext := make([]byte, len(data))
	d.XORKeyStream(plaintext, data)
	return plaintext, nil
}

func NewCBCEncrypter(block cipher.Block, iv []byte) cipher.Stream {
	var c cbc
	c.bm = cipher.NewCBCEncrypter(block, iv)
	return &c
}

func NewCBCDecrypter(block cipher.Block, iv []byte) cipher.Stream {
	var c cbc
	c.bm = cipher.NewCBCDecrypter(block, iv)
	return &c
}

type cbc struct {
	bm cipher.BlockMode
}

func (c *cbc) XORKeyStream(dst, src []byte) {
	c.bm.CryptBlocks(dst, src)
}
