package gm

import "github.com/tjfoc/gmsm/sm3"

func Sm3(data string) []byte {
	h := sm3.New()
	h.Write([]byte(data))
	return h.Sum(nil) // sm3.Sm3Sum([]byte(data))
}
