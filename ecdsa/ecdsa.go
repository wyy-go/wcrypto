package ecdsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"hash"
	"io/ioutil"
	"math/big"
	"os"
)

//var randKey = "lk0f7279c18d439459435s714797c9680335a320"

//var randSign = "22220316zafes20180lk7zafes20180619zafepikas"

var (
	privateBlockType = "ECDSA PRIVATE KEY"
	publicBlockType  = "ECDSA PUBLIC KEY"
)

// https://github.com/1william1/ecc

func GenerateKey(priFileName, pubFileName string, curve elliptic.Curve) error {
	priFile, err := os.Create(priFileName)
	if err != nil {
		return err
	}
	pubFile, err := os.Create(pubFileName)
	if err != nil {
		return err
	}
	defer priFile.Close()
	defer pubFile.Close()

	// gen privat key
	priKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return err
	}

	// use x509 codec
	priBytes, err := x509.MarshalECPrivateKey(priKey)
	if err != nil {
		return err
	}

	priBlock := pem.Block{
		Type:  privateBlockType,
		Bytes: priBytes,
	}

	if err := pem.Encode(priFile, &priBlock); err != nil {
		return err
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&priKey.PublicKey)
	if err != nil {
		return err
	}
	pubBlock := pem.Block{
		Type:  publicBlockType,
		Bytes: pubBytes,
	}

	if err := pem.Encode(pubFile, &pubBlock); err != nil {
		return err
	}
	return nil
}

// LoadEcdsaKey load privat key and public key
func LoadEcdsaKey(privPemFile, pubPemFile string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {

	var priKey *ecdsa.PrivateKey
	var pubKey *ecdsa.PublicKey

	pri, _ := ioutil.ReadFile(privPemFile)
	pub, _ := ioutil.ReadFile(pubPemFile)

	block, _ := pem.Decode(pri)
	var err error

	priKey, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	block, _ = pem.Decode(pub)
	var i interface{}
	i, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	// PubKey = (*ecdsa.PublicKey)(i)
	var ok bool
	pubKey, ok = i.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("the public conversion error")
	}

	return priKey, pubKey, nil
}

type Ecdsa struct {
	pubKeyPemContent []byte
	pubKeyBlock      *pem.Block
	pubKey           interface{}
	eccPubKey        *ecdsa.PublicKey
	eciesPubKey      *ecies.PublicKey
	//ok               bool

	privKeyPemContent []byte
	privKeyBlock      *pem.Block
	privKey           interface{}
	eccPrivKey        *ecdsa.PrivateKey
	eciesPrivKey      *ecies.PrivateKey
	//ok                bool

	hasher hash.Hash
}

func NewEcdsa(pubPemFile, priPemFile string, hashType crypto.Hash) (*Ecdsa, error) {
	var err error
	var ok bool

	ecc := &Ecdsa{}
	ecc.hasher = hashType.New()

	// 1. 读取公钥pem内容
	ecc.pubKeyPemContent, err = ioutil.ReadFile(pubPemFile)
	if err != nil {
		return nil, err
	}

	// 2. 使用pem解码
	ecc.pubKeyBlock, _ = pem.Decode(ecc.pubKeyPemContent)

	// 3. 使用x509解码
	ecc.pubKey, err = x509.ParsePKIXPublicKey(ecc.pubKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// 4. 转化为ecdsa的pubkey
	ecc.eccPubKey, ok = ecc.pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("获取ecdsa公钥失败")
	}

	// 5. 转化为ecies的pubkey
	ecc.eciesPubKey = ecies.ImportECDSAPublic(ecc.eccPubKey)

	//======================
	// 1. 获取私钥文件的内容
	ecc.privKeyPemContent, err = ioutil.ReadFile(priPemFile)
	if err != nil {
		return nil, err
	}

	// 2. 获取pem格式的block
	ecc.privKeyBlock, _ = pem.Decode(ecc.privKeyPemContent)

	// 3. x509解码
	ecc.eccPrivKey, err = x509.ParseECPrivateKey(ecc.privKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// 4. 转化为ecdsa格式的priKey
	//ecc.eccPrivKey, ok = ecc.privKey.(*ecdsa.PrivateKey)
	//if !ok {
	//	return nil, errors.New("获取ecc私钥失败")
	//}

	// 5. 转化为ecies格式的私钥
	ecc.eciesPrivKey = ecies.ImportECDSA(ecc.eccPrivKey)
	return ecc, nil
}

// 加密,只支持P256
func (e *Ecdsa) ECCEncript(src []byte) (dst []byte, err error) {
	dst, err = ecies.Encrypt(rand.Reader, e.eciesPubKey, src, nil, nil)
	return
}

// 解密,只支持P256
func (e *Ecdsa) ECCDecript(src []byte) (dst []byte, err error) {
	dst, err = e.eciesPrivKey.Decrypt(src, nil, nil)
	return
}

func (e *Ecdsa) ECCSign(src []byte) (dst []byte, err error) {

	var (
		r *big.Int
		s *big.Int
	)
	srcHash := e.hasher.Sum(src)

	r, s, err = ecdsa.Sign(rand.Reader, e.eccPrivKey, srcHash)
	if err != nil {
		return
	}
	dst = append(r.Bytes(), s.Bytes()...)
	return
}

func (e *Ecdsa) ECCVerify(src []byte, sig []byte) (err error) {

	var (
		isVerified bool
		r          big.Int
		s          big.Int
	)

	srcHash := e.hasher.Sum(src)

	r.SetBytes(sig[:len(sig)/2])
	s.SetBytes(sig[len(sig)/2:])
	isVerified = ecdsa.Verify(e.eccPubKey, srcHash, &r, &s)
	if !isVerified {
		err = errors.New("verify err")
	}
	return
}
