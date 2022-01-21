package wcrypto

type KeyIv struct {
	keyLen int
	ivLen  int
	key    string
	iv     string
}

func (k *KeyIv) KeyLen() int {
	return k.keyLen
}

func (k *KeyIv) IvLen() int {
	return k.ivLen
}

func (k *KeyIv) Key() []byte {
	return []byte(k.key)
}

func (k *KeyIv) Iv() []byte {
	return []byte(k.iv)
}

func (k KeyIv) CheckLen(key, iv string) error {
	if len(key) != k.keyLen {
		return KeySizeError(len(key))
	}

	if len(iv) != k.ivLen {
		return IvSizeError(len(iv))
	}
	return nil
}

func newKeyIvLen(keyLen, ivLen int) KeyIv {
	return KeyIv{
		keyLen: keyLen,
		ivLen:  ivLen,
	}
}

func newKeyIv(key, iv string) KeyIv {
	return KeyIv{
		key: key,
		iv:  iv,
	}
}
