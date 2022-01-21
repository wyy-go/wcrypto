package main

import (
	"fmt"
	"github.com/wyy-go/wcrypto"
)

func main() {
	key := "1234567899874563"
	iv := "qwertyuiopasdfgj"
	testText := "hello world"

	crypto, err := wcrypto.NewChipher(wcrypto.Aes128Cbc, key, iv)
	if err != nil {
		fmt.Println(err)
		return
	}
	cipherText, err := crypto.Encrypt(testText)
	if err != nil {
		fmt.Println(err)
		return
	}

	plainText, err := crypto.Decrypt(cipherText)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(plainText)

}
