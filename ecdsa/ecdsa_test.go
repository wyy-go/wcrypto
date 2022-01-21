package ecdsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	curves := []elliptic.Curve{
		elliptic.P224(),
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}

	for _, curve := range curves {
		priFileName := fmt.Sprintf("./testdata/ecdsa_private_key_%s.pem", curve.Params().Name)
		pubFileName := fmt.Sprintf("./testdata/ecdsa_public_key_%s.pem", curve.Params().Name)

		err := GenerateKey(priFileName, pubFileName, curve)
		require.NoError(t, err)
	}
}

func TestEcdsa(t *testing.T) {
	curve := elliptic.P256()

	priFileName := fmt.Sprintf("./testdata/ecdsa_private_key_%s.pem", curve.Params().Name)
	pubFileName := fmt.Sprintf("./testdata/ecdsa_public_key_%s.pem", curve.Params().Name)

	priKey, pubKey, err := LoadEcdsaKey(priFileName, pubFileName)
	require.NoError(t, err)

	data := []byte("hello")

	hashText := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, priKey, hashText[:])
	require.NoError(t, err)

	b := ecdsa.Verify(pubKey, hashText[:], r, s)
	require.True(t, b, "ecdsa verify failed")

	ecc, err := NewEcdsa(pubFileName, priFileName, crypto.SHA1)
	require.NoError(t, err)

	en, err := ecc.ECCEncript(data)
	require.NoError(t, err)

	_, err = ecc.ECCDecript(en)
	require.NoError(t, err)

	v, err := ecc.ECCSign(data)
	require.NoError(t, err)

	err = ecc.ECCVerify(data, v)
	require.NoError(t, err)
}
