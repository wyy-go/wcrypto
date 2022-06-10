package gm

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tjfoc/gmsm/sm4"
	"github.com/tjfoc/gmsm/x509"
)

func TestCreateKey(t *testing.T) {
	key := []byte("1234567890")
	privateKey, publicKey, err := CreateSM2Key()
	assert.NoError(t, err)
	err = CreatePrivatePem(privateKey, key, "")
	assert.NoError(t, err)
	err = CreatePublicPem(publicKey, "")
	assert.NoError(t, err)
}

func TestCrypt(t *testing.T) {
	data := "this is a test."
	key := []byte("1234567890")
	privateKey, err := ReadPrivatePem("./testdata/sm2Private.pem", key)
	assert.NoError(t, err)
	publicKey, err := ReadPublicPem("./testdata/sm2Public.pem")
	assert.NoError(t, err)

	cipherStr := Encrypt(data, publicKey)
	plainStr, err := Decrypt(cipherStr, privateKey)
	assert.NoError(t, err)
	assert.Equal(t, data, plainStr)
}

func TestSign(t *testing.T) {
	msg := "this is a test."
	key := []byte("1234567890")
	privateKey, err := ReadPrivatePem("./testdata/sm2Private.pem", key)
	assert.NoError(t, err)
	publicKey, err := ReadPublicPem("./testdata/sm2Public.pem")
	assert.NoError(t, err)

	sign, err := Sign(msg, privateKey, x509.SM3)
	assert.NoError(t, err)
	ok := Verify(msg, sign, publicKey)
	assert.NoError(t, err)
	assert.Equal(t, true, ok)
}

func TestSm3Sum(t *testing.T) {
	give := "123456"
	want := "207cf410532f92a47dee245ce9b11ff71f578ebd763eb3bbea44ebd043d018fb"
	out := hex.EncodeToString(Sm3(give))

	assert.Equal(t, want, out)
}

func TestSm4(t *testing.T) {
	key := []byte("1234567890abcdef")
	iv := make([]byte, sm4.BlockSize)
	data := []byte("this is test.")
	cipherText, err := EncryptWithSm4(key, iv, data)
	assert.NoError(t, err)
	plainText, err := DecryptWithSm4(key, iv, cipherText)
	assert.NoError(t, err)

	assert.Equal(t, data, plainText)
}
