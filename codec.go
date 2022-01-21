package wcrypto

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

type CodecType string

const (
	CodecTypeNone   CodecType = "None"
	CodecTypeBase64 CodecType = "Base64"
	CodecTypeHex    CodecType = "Hex"
)

var codecs = map[CodecType]Codec{
	CodecTypeNone:   &None{},
	CodecTypeBase64: &Base64{},
	CodecTypeHex:    &Hex{},
}

type Codec interface {
	Encode(plaintext []byte) string
	Decode(ciphertext string) ([]byte, error)
}

func getCodecByType(key CodecType) Codec {
	c, ok := codecs[key]
	if !ok {
		return nil
	}
	return c
}

type None struct {
}

func (c *None) Encode(plaintext []byte) string {
	return string(plaintext)
}
func (c *None) Decode(ciphertext string) ([]byte, error) {
	return []byte(ciphertext), nil
}

type Base64 struct{}

func (c *Base64) Encode(plaintext []byte) string {
	return base64.StdEncoding.EncodeToString(plaintext)
}
func (c *Base64) Decode(ciphertext string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(ciphertext)
}

type Hex struct{}

func (c *Hex) Encode(plaintext []byte) string {
	return fmt.Sprintf("%X", plaintext)
}
func (c *Hex) Decode(ciphertext string) ([]byte, error) {
	return hex.DecodeString(ciphertext)
}
