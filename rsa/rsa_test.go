package rsa

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRsa(t *testing.T) {

	testText := "hello world"
	t.Run("GenRsaKey", func(t *testing.T) {
		r := NewRsa(WithFormat(PKCS1), WithBits(2048))
		err := r.GenRsaKey()
		require.NoError(t, err)
	})

	t.Run("pkcs1", func(t *testing.T) {
		r := NewRsa(WithFormat(PKCS1), WithSignatureAlgorithm(SHA1),
			WithPrivatePemFile("./testdata/private_pkcs1.pem"),
			WithPublicPemFile("./testdata/public_pkcs1.pem"))
		_, _, err := r.LoadRsaKey()
		require.NoError(t, err)

		en, err := r.RsaEncrypt([]byte(testText))
		require.NoError(t, err)

		de, err := r.RsaDecrypt(en)
		require.NoError(t, err)

		require.Equal(t, testText, string(de))

		sig, err := r.RsaSign([]byte(testText))
		require.NoError(t, err)

		err = r.RsaVerySign([]byte(testText), sig)
		require.NoError(t, err)
	})

	t.Run("pkcs8", func(t *testing.T) {
		r := NewRsa(WithFormat(PKCS8), WithSignatureAlgorithm(SHA1),
			WithPrivatePemFile("./testdata/private_pkcs8.pem"),
			WithPublicPemFile("./testdata/public_pkcs8.pem"))
		_, _, err := r.LoadRsaKey()
		require.NoError(t, err)

		en, err := r.RsaEncrypt([]byte(testText))
		require.NoError(t, err)

		de, err := r.RsaDecrypt(en)
		require.NoError(t, err)

		require.Equal(t, testText, string(de))

		sig, err := r.RsaSign([]byte(testText))
		require.NoError(t, err)

		err = r.RsaVerySign([]byte(testText), sig)
		require.NoError(t, err)
	})

	t.Run("parse key", func(t *testing.T) {
		// 加解密
		publicKey := `
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxeAFkWk/oAABRjlDnI6ubgsHZ
PhB8qFZthAfodzDuU503oHvYonXDHWzMD0WsfM8EIJ43adY+tYAVv5NatnxUE91w
WsKqANYxAsf82Bj4D+PHcOaFhgOUy757sykwkibg27ITYnCfuNLLUzPs9y6r1tXy
Yjibu73jZM2YVNAIcwIDAQAB
-----END PUBLIC KEY-----`

		privateKey := `
-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALF4AWRaT+gAAFGO
UOcjq5uCwdk+EHyoVm2EB+h3MO5TnTege9iidcMdbMwPRax8zwQgnjdp1j61gBW/
k1q2fFQT3XBawqoA1jECx/zYGPgP48dw5oWGA5TLvnuzKTCSJuDbshNicJ+40stT
M+z3LqvW1fJiOJu7veNkzZhU0AhzAgMBAAECgYAXZMlSMDF+VJm2Jnt1rJcPfdIN
0AeeVxZlg1UDiMqzb+Q2k/ofWXMKkFNqJs05ao5jbeVNSq9KPuSueT10ZL/IoQzb
neGbfm4m3Da+UYDf42KVazQMTx5ZE6WwDncqPoIE3Q7zU9zz9Hxy16omnXCJfSOQ
cQCUHAEZitC+FhntIQJBAOq/M8Zrsql44lH5nOrEMoJmwvrI1VecDc/Xa1SHjxFS
1arEcTzKrMidR/Vit6kFIsHf9yhvk1Entoe4iEjqDyMCQQDBiUBhVaa1ZpLsvGa8
QMmTOSJHT8C9v+q6oMDjpcnBLvoAbKir/wgGJ7law+UKn75uVSVCHJCueEJhNSh/
ld5xAkEAiNfFGtoVYG2zoQ3dx41v1EyLRR5mH5g9BPgS/Ue4wuSC4fV5/XI4nwnw
tL9DSShRRquErPG98wUvhpav+7FV+QJAMiVzBgVgZb5HMYn7gKm00S3LoPicM05H
7sV6VUH+zcxzQKrm5XH2TUn7r/X0IdWUTRhIyCGIp3xHjtJsROq7MQJAOkZXWL4j
OBf8IPRH1A+gn0Vmlu15bJHxLFGoVpkvcSrFH11zvZXQUsoTuKzpkPPTFfq2xS6I
PWWXCwkI9toGGA==
-----END PRIVATE KEY-----
`

		r := NewRsa(WithFormat(PKCS8), WithSignatureAlgorithm(SHA1))

		err := r.ParsePemKey(publicKey, privateKey)
		require.NoError(t, err)

		en, err := r.RsaEncrypt([]byte(testText))
		require.NoError(t, err)

		de, err := r.RsaDecrypt(en)
		require.NoError(t, err)

		require.Equal(t, testText, string(de))

		sig, err := r.RsaSign([]byte(testText))
		require.NoError(t, err)

		err = r.RsaVerySign([]byte(testText), sig)
		require.NoError(t, err)
	})

	t.Run("parse base64 key", func(t *testing.T) {
		privateKey := "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALF4AWRaT+gAAFGOUOcjq5uCwdk+EHyoVm2EB+h3MO5TnTege9iidcMdbMwPRax8zwQgnjdp1j61gBW/k1q2fFQT3XBawqoA1jECx/zYGPgP48dw5oWGA5TLvnuzKTCSJuDbshNicJ+40stTM+z3LqvW1fJiOJu7veNkzZhU0AhzAgMBAAECgYAXZMlSMDF+VJm2Jnt1rJcPfdIN0AeeVxZlg1UDiMqzb+Q2k/ofWXMKkFNqJs05ao5jbeVNSq9KPuSueT10ZL/IoQzbneGbfm4m3Da+UYDf42KVazQMTx5ZE6WwDncqPoIE3Q7zU9zz9Hxy16omnXCJfSOQcQCUHAEZitC+FhntIQJBAOq/M8Zrsql44lH5nOrEMoJmwvrI1VecDc/Xa1SHjxFS1arEcTzKrMidR/Vit6kFIsHf9yhvk1Entoe4iEjqDyMCQQDBiUBhVaa1ZpLsvGa8QMmTOSJHT8C9v+q6oMDjpcnBLvoAbKir/wgGJ7law+UKn75uVSVCHJCueEJhNSh/ld5xAkEAiNfFGtoVYG2zoQ3dx41v1EyLRR5mH5g9BPgS/Ue4wuSC4fV5/XI4nwnwtL9DSShRRquErPG98wUvhpav+7FV+QJAMiVzBgVgZb5HMYn7gKm00S3LoPicM05H7sV6VUH+zcxzQKrm5XH2TUn7r/X0IdWUTRhIyCGIp3xHjtJsROq7MQJAOkZXWL4jOBf8IPRH1A+gn0Vmlu15bJHxLFGoVpkvcSrFH11zvZXQUsoTuKzpkPPTFfq2xS6IPWWXCwkI9toGGA=="
		publicKey := "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxeAFkWk/oAABRjlDnI6ubgsHZPhB8qFZthAfodzDuU503oHvYonXDHWzMD0WsfM8EIJ43adY+tYAVv5NatnxUE91wWsKqANYxAsf82Bj4D+PHcOaFhgOUy757sykwkibg27ITYnCfuNLLUzPs9y6r1tXyYjibu73jZM2YVNAIcwIDAQAB"

		r := NewRsa(WithFormat(PKCS8), WithSignatureAlgorithm(SHA1))

		err := r.ParseBase64Key(publicKey, privateKey)
		require.NoError(t, err)

		en, err := r.RsaEncrypt([]byte(testText))
		require.NoError(t, err)

		de, err := r.RsaDecrypt(en)
		require.NoError(t, err)

		require.Equal(t, testText, string(de))

		sig, err := r.RsaSign([]byte(testText))
		require.NoError(t, err)

		err = r.RsaVerySign([]byte(testText), sig)
		require.NoError(t, err)
	})

}
