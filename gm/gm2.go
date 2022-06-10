package gm

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

// https://github.com/emmansun/gmsm

// CreateSM2Key Randomly generate public and private keys
func CreateSM2Key() (privateKey *sm2.PrivateKey, publicKey *sm2.PublicKey, err error) {

	// Generate sm2 key pair
	privateKey, err = sm2.GenerateKey(rand.Reader)
	if err != nil {
		return
	}

	publicKey = privateKey.Public().(*sm2.PublicKey)

	return
}

// CreatePrivatePem Create private key file
func CreatePrivatePem(privateKey *sm2.PrivateKey, pwd []byte, path string) error {
	privateKeyTopem, err := x509.WritePrivateKeyToPem(privateKey, pwd)
	if err != nil {
		return err
	}

	if len(path) < 1 {
		path = "./testdata/sm2Private.pem"
	}

	paths, _ := filepath.Split(path)
	err = os.MkdirAll(paths, os.ModePerm)
	if err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(privateKeyTopem)
	if err != nil {
		return err
	}

	return nil
}

// CreatePublicPem Create public key file
func CreatePublicPem(publicKey *sm2.PublicKey, path string) error {
	publicKeyToPem, err := x509.WritePublicKeyToPem(publicKey)
	if err != nil {
		return err
	}

	if len(path) < 1 {
		path = "./testdata/sm2Public.pem"
	}

	paths, _ := filepath.Split(path)
	err = os.MkdirAll(paths, os.ModePerm)
	if err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(publicKeyToPem)
	if err != nil {
		return err
	}
	return nil
}

// ReadPrivatePem Read private key file
func ReadPrivatePem(path string, pwd []byte) (*sm2.PrivateKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, fileInfo.Size(), fileInfo.Size())
	_, err = file.Read(buf)
	if err != nil {
		return nil, err
	}

	privateKey, err := x509.ReadPrivateKeyFromPem(buf, pwd)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// ReadPublicPem Read public key file
func ReadPublicPem(path string) (*sm2.PublicKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, fileInfo.Size(), fileInfo.Size())
	_, err = file.Read(buf)
	if err != nil {
		return nil, err
	}

	publicKey, err := x509.ReadPublicKeyFromPem(buf)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func Encrypt(data string, publicKey *sm2.PublicKey) string {
	dataByte := []byte(data)

	cipherTxt, err := publicKey.EncryptAsn1(dataByte, rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	cipherStr := hex.EncodeToString(cipherTxt)
	return cipherStr
}

func Decrypt(cipherStr string, privateKey *sm2.PrivateKey) (string, error) {
	bytes, _ := hex.DecodeString(cipherStr)

	var dataByte []byte

	dataByte, err := privateKey.DecryptAsn1(bytes)
	if err != nil {
		return "", err
	}

	str := (*string)(unsafe.Pointer(&dataByte))
	return *str, nil
}

func Sign(msg string, privateKey *sm2.PrivateKey, signer crypto.SignerOpts) (string, error) {
	dataByte := []byte(msg)

	signByte, err := privateKey.Sign(rand.Reader, dataByte, signer)
	if err != nil {
		return "", err
	}
	sign := hex.EncodeToString(signByte)
	return sign, nil
}

func Verify(msg string, sign string, publicKey *sm2.PublicKey) bool {
	msgBytes := []byte(msg)
	signBytes, _ := hex.DecodeString(sign)
	verify := publicKey.Verify(msgBytes, signBytes)
	return verify
}
