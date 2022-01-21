package wcrypto

import (
	"bytes"
	"fmt"
)

type PaddingType string

const (
	PaddingTypeNone     PaddingType = "NonePadding"
	PaddingTypeAnsiX923 PaddingType = "AnsiX923Padding"
	PaddingTypeISO10126 PaddingType = "ISO10126Padding"
	PaddingTypeISO97971 PaddingType = "ISO97971Padding"
	PaddingTypePKCS7    PaddingType = "PKCS7Padding"
	PaddingTypePKCS5    PaddingType = "PKCS5Padding"
	PaddingTypeZero     PaddingType = "ZeroPadding"
)

var paddings = map[PaddingType]Padding{
	PaddingTypeNone:     &NonePadding{},
	PaddingTypeAnsiX923: &AnsiX923Padding{},
	PaddingTypeISO10126: &ISO10126Padding{},
	PaddingTypeISO97971: &ISO97971Padding{},
	PaddingTypePKCS7:    &PKCS7Padding{},
	PaddingTypePKCS5:    &PKCS5Padding{},
	PaddingTypeZero:     &ZeroPadding{},
}

func getPaddingByType(key PaddingType) Padding {
	p, ok := paddings[key]
	if !ok {
		return nil
	}
	return p
}

type Padding interface {
	Padding(ciphertext []byte, blockSize int) ([]byte, error)
	UnPadding(origData []byte) ([]byte, error)
}

func padSize(dataSize, blockSize int) (padding int) {
	padding = blockSize - dataSize%blockSize
	return
}

type NonePadding struct {
}

func (p *NonePadding) Padding(ciphertext []byte, blockSize int) ([]byte, error) {
	return ciphertext, nil
}

func (p *NonePadding) UnPadding(origData []byte) ([]byte, error) {
	return origData, nil
}

type AnsiX923Padding struct {
}

// Padding ANSI X.923
func (p *AnsiX923Padding) Padding(plaintext []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 255 {
		return nil, fmt.Errorf("crypt.AnsiX923Padding blockSize is out of bounds: %d", blockSize)
	}
	padding := padSize(len(plaintext), blockSize)
	padtext := append(bytes.Repeat([]byte{byte(0)}, padding-1), byte(padding))
	return append(plaintext, padtext...), nil
}

func (p *AnsiX923Padding) UnPadding(ciphertext []byte) ([]byte, error) {
	length := len(ciphertext)
	unpadding := int(ciphertext[length-1])
	if length-unpadding < length-2 {
		pad := ciphertext[length-unpadding : length-2]
		for _, v := range pad {
			if int(v) != 0 {
				return nil, fmt.Errorf("crypt.AnsiX923UnPadding invalid padding found")
			}
		}
	}
	return ciphertext[0 : length-unpadding], nil
}

type ISO10126Padding struct {
}

// Padding ISO10126 implements ISO 10126 byte padding. This has been withdrawn in 2007.
func (p *ISO10126Padding) Padding(plaintext []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 256 {
		return nil, fmt.Errorf("crypt.ISO10126Padding blockSize is out of bounds: %d", blockSize)
	}
	padding := padSize(len(plaintext), blockSize)
	padtext := append([]byte(RandStringBytes(padding-1)), byte(padding))
	return append(plaintext, padtext...), nil
}

func (p *ISO10126Padding) UnPadding(ciphertext []byte) ([]byte, error) {
	length := len(ciphertext)
	unpadding := int(ciphertext[length-1])
	return ciphertext[:length-unpadding], nil
}

type ISO97971Padding struct {
}

func (p *ISO97971Padding) Padding(plaintext []byte, blockSize int) ([]byte, error) {
	plaintext = append(plaintext, 0x80)
	padding := blockSize - len(plaintext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(plaintext, padtext...), nil
}

func (p *ISO97971Padding) UnPadding(ciphertext []byte) ([]byte, error) {
	b := bytes.TrimRightFunc(ciphertext, func(r rune) bool { return r == rune(0) })
	return b[:len(b)-1], nil
}

type PKCS7Padding struct {
}

// Padding PKCS7
func (p *PKCS7Padding) Padding(plainText []byte, blockSize int) ([]byte, error) {

	padding := padSize(len(plainText), blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plainText, padText...), nil
}

func (p *PKCS7Padding) UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)

	unpadding := int(origData[length-1])

	var pad = origData[length-unpadding : length-1]
	for _, v := range pad {
		if int(v) != unpadding {
			return nil, fmt.Errorf("crypt.PKCS7UnPadding invalid padding found")
		}
	}
	return origData[:length-unpadding], nil
}

type PKCS5Padding struct {
}

func (p *PKCS5Padding) Padding(ciphertext []byte, blockSize int) ([]byte, error) {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...), nil
}

func (p *PKCS5Padding) UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)], nil
}

// ZeroPadding
// 使用0填充有个缺点，当元数据尾部也存在0时，在unpadding时可能会存在问题
type ZeroPadding struct {
}

func (p *ZeroPadding) Padding(ciphertext []byte, blockSize int) ([]byte, error) {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...), nil
}

func (p *ZeroPadding) UnPadding(origData []byte) ([]byte, error) {
	return bytes.TrimFunc(origData,
		func(r rune) bool {
			return r == rune(0)
		}), nil
}
