package wcrypto

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)
import "github.com/stretchr/testify/require"

func TestCodec(t *testing.T) {
	testText := "hello world"
	t.Run("none", func(t *testing.T) {
		codec := getCodecByType(CodecTypeNone)
		cipherText := codec.Encode([]byte(testText))
		plainText, err := codec.Decode(cipherText)
		require.NoError(t, err)
		assert.Equal(t, testText, string(plainText), fmt.Errorf("codec: %s", "none"))
	})

	t.Run("hex", func(t *testing.T) {
		codec := getCodecByType(CodecTypeHex)
		cipherText := codec.Encode([]byte(testText))
		plainText, err := codec.Decode(cipherText)
		require.NoError(t, err)
		assert.Equal(t, testText, string(plainText), fmt.Errorf("codec: %s", "hex"))
	})

	t.Run("base64", func(t *testing.T) {
		codec := getCodecByType(CodecTypeBase64)
		cipherText := codec.Encode([]byte(testText))
		plainText, err := codec.Decode(cipherText)
		require.NoError(t, err)
		assert.Equal(t, testText, string(plainText), fmt.Errorf("codec: %s", "base64"))
	})
}

func TestPadding(t *testing.T) {
	padding := getPaddingByType(PaddingTypeNone)
	require.NotNil(t, padding)
}

func TestCryptoMethod(t *testing.T) {
	testText := "hello world"

	methods := getCryptoMethod()
	for _, method := range methods {
		t.Run(string(method), func(t *testing.T) {
			keyIv, err := getCryptoMethodKeyIv(method)
			require.NoError(t, err)
			key := RandStringBytes(keyIv.KeyLen())
			iv := RandStringBytes(keyIv.IvLen())

			crypto, err := NewChipher(method, key, iv)
			require.NoError(t, err)
			cipherText, err := crypto.Encrypt(testText)

			require.NoError(t, err)
			plainText, err := crypto.Decrypt(cipherText)
			require.NoError(t, err)

			assert.Equal(t, testText, plainText, fmt.Errorf("method: %s", method))
		})
	}
}

func TestCryptoMethodWithCodec(t *testing.T) {
	testText := "hello world"

	methods := getCryptoMethod()
	for _, method := range methods {
		t.Run(string(method), func(t *testing.T) {
			keyIv, err := getCryptoMethodKeyIv(method)
			require.NoError(t, err)
			key := RandStringBytes(keyIv.KeyLen())
			iv := RandStringBytes(keyIv.IvLen())

			crypto, err := NewChipher(method, key, iv, WithCodec(CodecTypeBase64))
			require.NoError(t, err)
			cipherText, err := crypto.Encrypt(testText)

			require.NoError(t, err)
			plainText, err := crypto.Decrypt(cipherText)
			require.NoError(t, err)

			assert.Equal(t, testText, plainText, fmt.Errorf("method: %s", method))
		})
	}
}

func TestCryptoMethodWithPadding(t *testing.T) {
	testText := "hello world"

	methods := getCryptoMethod()
	for _, method := range methods {
		t.Run(string(method), func(t *testing.T) {
			keyIv, err := getCryptoMethodKeyIv(method)
			require.NoError(t, err)
			key := RandStringBytes(keyIv.KeyLen())
			iv := RandStringBytes(keyIv.IvLen())

			crypto, err := NewChipher(method, key, iv, WithPadding(PaddingTypeAnsiX923))
			require.NoError(t, err)
			cipherText, err := crypto.Encrypt(testText)

			require.NoError(t, err)
			plainText, err := crypto.Decrypt(cipherText)
			require.NoError(t, err)

			assert.Equal(t, testText, plainText, fmt.Errorf("method: %s", method))
		})
	}
}
