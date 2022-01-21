package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"
	"os"
)

type Rsa struct {
	opts   *Options
	priKey *rsa.PrivateKey
	pubKey *rsa.PublicKey
}

func NewRsa(opts ...Option) *Rsa {
	options := newOptions(opts...)
	return &Rsa{
		opts: options,
	}
}

// GenRsaKey RSA公钥私钥产生
func (r *Rsa) GenRsaKey() error {

	privateKey, err := rsa.GenerateKey(rand.Reader, r.opts.bits)
	if err != nil {
		return err
	}
	var derStream []byte

	if r.opts.format == PKCS1 {
		derStream = x509.MarshalPKCS1PrivateKey(privateKey)

	} else if r.opts.format == PKCS8 {
		derStream, err = x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return err
		}
	} else {
		return errors.New("format err")
	}

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}

	file, err := os.Create(r.opts.priPemFile)
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}

	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	file, err = os.Create(r.opts.pukPemFile)
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

func (r *Rsa) RsaSign(data []byte) ([]byte, error) {

	var h hash.Hash
	var o crypto.Hash
	if r.opts.signatureAlgorithm == MD5 {
		h = crypto.MD5.New()
		o = crypto.MD5
	} else if r.opts.signatureAlgorithm == SHA1 {
		h = sha1.New()
		o = crypto.SHA1
	} else {
		return nil, errors.New("signature algorithm err")
	}

	h.Write(data)
	hashed := h.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, r.priKey, o, hashed[:])
	if err != nil {
		fmt.Printf("Error from signing: %s\n", err)
		return nil, err
	}

	return signature, nil
}

func (r *Rsa) RsaVerySign(origData, signData []byte) error {
	h := sha1.New()
	h.Write(origData)
	return rsa.VerifyPKCS1v15(r.pubKey, crypto.SHA1, h.Sum(nil), signData)
}

func (r *Rsa) RsaEncrypt(origData []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, r.pubKey, origData)
}

func (r *Rsa) RsaDecrypt(ciphertext []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, r.priKey, ciphertext)
}

// LoadRsaKey 加载私匙公匙
func (r *Rsa) LoadRsaKey() (*rsa.PrivateKey, *rsa.PublicKey, error) {

	var priKey *rsa.PrivateKey
	var pubKey *rsa.PublicKey

	pri, _ := ioutil.ReadFile(r.opts.priPemFile)
	pub, _ := ioutil.ReadFile(r.opts.pukPemFile)
	// 解码私匙
	block, _ := pem.Decode(pri)
	var err error

	if r.opts.format == PKCS1 {
		privInterface, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		priKey = privInterface
	} else if r.opts.format == PKCS8 {
		privInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		priKey = privInterface.(*rsa.PrivateKey)
	} else {
		return nil, nil, errors.New("format err")
	}

	block, _ = pem.Decode(pub)
	var i interface{}
	i, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	// PubKey = (*ecdsa.PublicKey)(i)
	var ok bool
	pubKey, ok = i.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("the public conversion error")
	}

	r.pubKey = pubKey
	r.priKey = priKey
	return priKey, pubKey, nil
}

func (r *Rsa) ParsePemKey(publicKey, privateKey string) error {

	var priKey *rsa.PrivateKey
	var pubKey *rsa.PublicKey

	block, _ := pem.Decode([]byte(privateKey))
	var err error

	if r.opts.format == PKCS1 {
		privInterface, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		priKey = privInterface
	} else if r.opts.format == PKCS8 {
		privInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		priKey = privInterface.(*rsa.PrivateKey)
	} else {
		return errors.New("format err")
	}

	block, _ = pem.Decode([]byte(publicKey))
	var i interface{}
	i, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	// PubKey = (*ecdsa.PublicKey)(i)
	var ok bool
	pubKey, ok = i.(*rsa.PublicKey)
	if !ok {
		return errors.New("the public conversion error")
	}

	r.pubKey = pubKey
	r.priKey = priKey
	return nil
}

func (r *Rsa) ParseBase64Key(base64PublicKey, base64PrivateKey string) error {

	var priKey *rsa.PrivateKey
	var pubKey *rsa.PublicKey

	puk, err := base64.StdEncoding.DecodeString(base64PublicKey)
	if err != nil {
		return err
	}

	prk, err := base64.StdEncoding.DecodeString(base64PrivateKey)
	if err != nil {
		return err
	}

	if r.opts.format == PKCS1 {
		privInterface, err := x509.ParsePKCS1PrivateKey(prk)
		if err != nil {
			return err
		}
		priKey = privInterface
	} else if r.opts.format == PKCS8 {
		privInterface, err := x509.ParsePKCS8PrivateKey(prk)
		if err != nil {
			return err
		}
		priKey = privInterface.(*rsa.PrivateKey)
	} else {
		return errors.New("format err")
	}

	var i interface{}
	i, err = x509.ParsePKIXPublicKey(puk)
	if err != nil {
		return err
	}
	// PubKey = (*ecdsa.PublicKey)(i)
	var ok bool
	pubKey, ok = i.(*rsa.PublicKey)
	if !ok {
		return errors.New("the public conversion error")
	}

	r.pubKey = pubKey
	r.priKey = priKey
	return nil
}
