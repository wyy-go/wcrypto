# wcrypto

![GitHub Repo stars](https://img.shields.io/github/stars/wyy-go/wcrypto?style=social)
![GitHub](https://img.shields.io/github/license/wyy-go/wcrypto)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/wyy-go/wcrypto)
![GitHub all releases](https://img.shields.io/github/downloads/wyy-go/wcrypto/total)
![GitHub CI Status](https://img.shields.io/github/workflow/status/wyy-go/wcrypto/ci?label=CI)
![GitHub Release Status](https://img.shields.io/github/workflow/status/wyy-go/wcrypto/Release?label=release)
[![Go Report Card](https://goreportcard.com/badge/github.com/wyy-go/wcrypto)](https://goreportcard.com/report/github.com/wyy-go/wcrypto)
[![Go.Dev reference](https://img.shields.io/badge/go.dev-reference-blue?logo=go&logoColor=white)](https://pkg.go.dev/github.com/wyy-go/wcrypto?tab=doc)
[![codecov](https://codecov.io/gh/wyy-go/wcrypto/branch/main/graph/badge.svg)](https://codecov.io/gh/wyy-go/wcrypto)

## Example
```go
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


```

## Reference
* https://mojotv.cn/go/golang-crypto
* https://cloud.tencent.com/developer/chapter/12831
* https://gchq.github.io/CyberChef/
* https://www.cnblogs.com/LiuYanYGZ/p/10438819.html


需要Padding的有：CBC（，PCBC也需要，本文未涉及该加密模式）、ECB。
不需要Padding的有：CFB、OFB、CTR。

以上五种分组模式中，ECB模式很容易被破解，如今已经很少再使用，其余四种分组模式各有千秋。
但极力推荐CBC模式和CTR模式，尤其是CTR模式，不需要填充，代码实现起来很方便。
而且加密和解密的方法是一样的，并且可以实现并发分组，效率高，安全性也有保障