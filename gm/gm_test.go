package gm

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tjfoc/gmsm/sm2"
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

func TestReadHexPrivateKey1(t *testing.T) {
	// read hex private key
	privateKeyByte := []byte("888DB2B7CD4B8E184258D93CF0C44ED4FD2E85DC34B953D2A30F4939CCCD5369")
	msg := []byte("this is a test.")
	uid := []byte("12345678")

	curve := sm2.P256Sm2()
	curve.ScalarBaseMult(privateKeyByte)
	privateKey := new(sm2.PrivateKey)
	privateKey.PublicKey.Curve = curve
	privateKey.D, _ = new(big.Int).SetString(string(privateKeyByte), 16)
	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(privateKeyByte)

	r, s, err := sm2.Sm2Sign(privateKey, msg, uid, rand.Reader)
	assert.NoError(t, err)

	ss, err := sm2.SignDigitToSignData(r, s)
	assert.NoError(t, err)
	sg := base64.StdEncoding.EncodeToString(ss)
	t.Log(sg)
}

func TestReadHexPrivateKey2(t *testing.T) {
	// read hex private key
	privateKeyStr := "888DB2B7CD4B8E184258D93CF0C44ED4FD2E85DC34B953D2A30F4939CCCD5369"
	msg := []byte("this is a test.")
	uid := []byte("12345678")

	privateKey, err := x509.ReadPrivateKeyFromHex(privateKeyStr)
	assert.NoError(t, err)

	r, s, err := sm2.Sm2Sign(privateKey, msg, uid, rand.Reader)
	assert.NoError(t, err)
	ss, err := sm2.SignDigitToSignData(r, s)
	assert.NoError(t, err)
	sg := base64.StdEncoding.EncodeToString(ss)
	t.Log(sg)
}
