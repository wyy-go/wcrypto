package wcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"golang.org/x/crypto/tea"
)

type (
	CryptoMethod string
	NewCipher    func(key []byte) (cipher.Block, error)
	NewStream    func(key, iv []byte) (cipher.Stream, error)
)

const (
	Aes128Cbc     CryptoMethod = "aes-128-cbc"
	Aes192Cbc     CryptoMethod = "aes-192-cbc"
	Aes256Cbc     CryptoMethod = "aes-256-cbc"
	Aes128Cfb     CryptoMethod = "aes-128-cfb"
	Aes192Cfb     CryptoMethod = "aes-192-cfb"
	Aes256Cfb     CryptoMethod = "aes-256-cfb"
	Aes128Ctr     CryptoMethod = "aes-128-ctr"
	Aes192Ctr     CryptoMethod = "aes-192-ctr"
	Aes256Ctr     CryptoMethod = "aes-256-ctr"
	Aes128Ofb     CryptoMethod = "aes-128-ofb"
	Aes192Ofb     CryptoMethod = "aes-192-ofb"
	Aes256Ofb     CryptoMethod = "aes-256-ofb"
	DesCbc        CryptoMethod = "des-cbc"
	DesCfb        CryptoMethod = "des-cfb"
	DesCtr        CryptoMethod = "des-ctr"
	DesOfb        CryptoMethod = "des-ofb"
	Des3Cfb       CryptoMethod = "3des-cfb"
	Des3Ctr       CryptoMethod = "3des-ctr"
	Des3Ofb       CryptoMethod = "3des-ofb"
	BlowfishCbc   CryptoMethod = "blowfish-cbc"
	BlowfishCfb   CryptoMethod = "blowfish-cfb"
	BlowfishCtr   CryptoMethod = "blowfish-ctr"
	BlowfishOfb   CryptoMethod = "blowfish-ofb"
	Cast5Cbc      CryptoMethod = "cast5-cbc"
	Cast5Cfb      CryptoMethod = "cast5-cfb"
	Cast5Ctr      CryptoMethod = "cast5-ctr"
	Cast5Ofb      CryptoMethod = "cast5-ofb"
	Twofish128CBC CryptoMethod = "twofish-128-cbc"
	Twofish192CBC CryptoMethod = "twofish-192-cbc"
	Twofish256CBC CryptoMethod = "twofish-256-cbc"
	Twofish128Cfb CryptoMethod = "twofish-128-cfb"
	Twofish192Cfb CryptoMethod = "twofish-192-cfb"
	Twofish256Cfb CryptoMethod = "twofish-256-cfb"
	Twofish128Ctr CryptoMethod = "twofish-128-ctr"
	Twofish192Ctr CryptoMethod = "twofish-192-ctr"
	Twofish256Ctr CryptoMethod = "twofish-256-ctr"
	Twofish128Ofb CryptoMethod = "twofish-128-ofb"
	Twofish192Ofb CryptoMethod = "twofish-192-ofb"
	Twofish256Ofb CryptoMethod = "twofish-256-ofb"
	XteaCbc       CryptoMethod = "xtea-cbc"
	XteaCfb       CryptoMethod = "xtea-cfb"
	XteaCtr       CryptoMethod = "xtea-ctr"
	XteaOfb       CryptoMethod = "xtea-ofb"
	TeaCbc        CryptoMethod = "tea-cbc"
	TeaCfb        CryptoMethod = "tea-cfb"
	TeaCtr        CryptoMethod = "tea-ctr"
	TeaOfb        CryptoMethod = "tea-ofb"
	Rc4Md5        CryptoMethod = "rc4-md5"
	Rc4Md5_6      CryptoMethod = "rc4-md5-6"
	Chacha20      CryptoMethod = "chacha20"
	Chacha20_Ietf CryptoMethod = "chacha20-ietf"
	Salsa20       CryptoMethod = "salsa20"
)

type Crypto interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
}

type cipherConfig struct {
	KeyIv
	newCipher NewCipher
	mode      Mode
	padding   Padding
	codec     Codec
}

type simpleCipherConfig struct {
	KeyIv
	newStream NewStream
	codec     Codec
}

type Cipher struct {
	options *Options
}

var ciphers = map[CryptoMethod]cipherConfig{
	Aes128Cbc:     {newKeyIvLen(16, 16), aes.NewCipher, getModeByType(BlockModeCBC), getPaddingByType(PaddingTypePKCS7), getCodecByType(CodecTypeNone)},
	Aes192Cbc:     {newKeyIvLen(24, 16), aes.NewCipher, getModeByType(BlockModeCBC), getPaddingByType(PaddingTypePKCS7), getCodecByType(CodecTypeNone)},
	Aes256Cbc:     {newKeyIvLen(32, 16), aes.NewCipher, getModeByType(BlockModeCBC), getPaddingByType(PaddingTypePKCS7), getCodecByType(CodecTypeNone)},
	Aes128Cfb:     {newKeyIvLen(16, 16), aes.NewCipher, getModeByType(BlockModeCFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Aes192Cfb:     {newKeyIvLen(24, 16), aes.NewCipher, getModeByType(BlockModeCFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Aes256Cfb:     {newKeyIvLen(32, 16), aes.NewCipher, getModeByType(BlockModeCFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Aes128Ctr:     {newKeyIvLen(16, 16), aes.NewCipher, getModeByType(BlockModeCTR), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Aes192Ctr:     {newKeyIvLen(24, 16), aes.NewCipher, getModeByType(BlockModeCTR), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Aes256Ctr:     {newKeyIvLen(32, 16), aes.NewCipher, getModeByType(BlockModeCTR), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Aes128Ofb:     {newKeyIvLen(16, 16), aes.NewCipher, getModeByType(BlockModeOFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Aes192Ofb:     {newKeyIvLen(24, 16), aes.NewCipher, getModeByType(BlockModeOFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Aes256Ofb:     {newKeyIvLen(32, 16), aes.NewCipher, getModeByType(BlockModeOFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	DesCbc:        {newKeyIvLen(8, 8), des.NewCipher, getModeByType(BlockModeCBC), getPaddingByType(PaddingTypePKCS7), getCodecByType(CodecTypeNone)},
	DesCfb:        {newKeyIvLen(8, 8), des.NewCipher, getModeByType(BlockModeCFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	DesCtr:        {newKeyIvLen(8, 8), des.NewCipher, getModeByType(BlockModeCTR), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	DesOfb:        {newKeyIvLen(8, 8), des.NewCipher, getModeByType(BlockModeOFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Des3Cfb:       {newKeyIvLen(24, 8), des.NewTripleDESCipher, getModeByType(BlockModeCFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Des3Ctr:       {newKeyIvLen(24, 8), des.NewTripleDESCipher, getModeByType(BlockModeCTR), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Des3Ofb:       {newKeyIvLen(24, 8), des.NewTripleDESCipher, getModeByType(BlockModeOFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	BlowfishCbc:   {newKeyIvLen(16, 8), NewBlowfishCipher, getModeByType(BlockModeCBC), getPaddingByType(PaddingTypePKCS7), getCodecByType(CodecTypeNone)},
	BlowfishCfb:   {newKeyIvLen(16, 8), NewBlowfishCipher, getModeByType(BlockModeCFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	BlowfishCtr:   {newKeyIvLen(16, 8), NewBlowfishCipher, getModeByType(BlockModeCTR), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	BlowfishOfb:   {newKeyIvLen(16, 8), NewBlowfishCipher, getModeByType(BlockModeOFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Cast5Cbc:      {newKeyIvLen(16, 8), NewCast5Cipher, getModeByType(BlockModeCBC), getPaddingByType(PaddingTypePKCS7), getCodecByType(CodecTypeNone)},
	Cast5Cfb:      {newKeyIvLen(16, 8), NewCast5Cipher, getModeByType(BlockModeCFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Cast5Ctr:      {newKeyIvLen(16, 8), NewCast5Cipher, getModeByType(BlockModeCTR), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Cast5Ofb:      {newKeyIvLen(16, 8), NewCast5Cipher, getModeByType(BlockModeOFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Twofish128CBC: {newKeyIvLen(16, 16), NewTwofishCipher, getModeByType(BlockModeCBC), getPaddingByType(PaddingTypePKCS7), getCodecByType(CodecTypeNone)},
	Twofish192CBC: {newKeyIvLen(24, 16), NewTwofishCipher, getModeByType(BlockModeCBC), getPaddingByType(PaddingTypePKCS7), getCodecByType(CodecTypeNone)},
	Twofish256CBC: {newKeyIvLen(32, 16), NewTwofishCipher, getModeByType(BlockModeCBC), getPaddingByType(PaddingTypePKCS7), getCodecByType(CodecTypeNone)},
	Twofish128Cfb: {newKeyIvLen(16, 16), NewTwofishCipher, getModeByType(BlockModeCFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Twofish192Cfb: {newKeyIvLen(24, 16), NewTwofishCipher, getModeByType(BlockModeCFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Twofish256Cfb: {newKeyIvLen(32, 16), NewTwofishCipher, getModeByType(BlockModeCFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Twofish128Ctr: {newKeyIvLen(16, 16), NewTwofishCipher, getModeByType(BlockModeCTR), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Twofish192Ctr: {newKeyIvLen(24, 16), NewTwofishCipher, getModeByType(BlockModeCTR), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Twofish256Ctr: {newKeyIvLen(32, 16), NewTwofishCipher, getModeByType(BlockModeCTR), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Twofish128Ofb: {newKeyIvLen(16, 16), NewTwofishCipher, getModeByType(BlockModeOFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Twofish192Ofb: {newKeyIvLen(24, 16), NewTwofishCipher, getModeByType(BlockModeOFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	Twofish256Ofb: {newKeyIvLen(32, 16), NewTwofishCipher, getModeByType(BlockModeOFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	XteaCbc:       {newKeyIvLen(16, 8), NewXteaCipher, getModeByType(BlockModeCBC), getPaddingByType(PaddingTypePKCS7), getCodecByType(CodecTypeNone)},
	XteaCfb:       {newKeyIvLen(16, 8), NewXteaCipher, getModeByType(BlockModeCFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	XteaCtr:       {newKeyIvLen(16, 8), NewXteaCipher, getModeByType(BlockModeCTR), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	XteaOfb:       {newKeyIvLen(16, 8), NewXteaCipher, getModeByType(BlockModeOFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	TeaCbc:        {newKeyIvLen(16, 8), tea.NewCipher, getModeByType(BlockModeCBC), getPaddingByType(PaddingTypePKCS7), getCodecByType(CodecTypeNone)},
	TeaCfb:        {newKeyIvLen(16, 8), tea.NewCipher, getModeByType(BlockModeCFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	TeaCtr:        {newKeyIvLen(16, 8), tea.NewCipher, getModeByType(BlockModeCTR), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
	TeaOfb:        {newKeyIvLen(16, 8), tea.NewCipher, getModeByType(BlockModeOFB), getPaddingByType(PaddingTypeNone), getCodecByType(CodecTypeNone)},
}

var simpleCiphers = map[CryptoMethod]simpleCipherConfig{
	Rc4Md5:        {newKeyIvLen(16, 16), NewRc4Md5, &Hex{}},
	Rc4Md5_6:      {newKeyIvLen(16, 6), NewRc4Md5, &Hex{}},
	Chacha20:      {newKeyIvLen(32, 12), NewChacha20, &Hex{}},
	Chacha20_Ietf: {newKeyIvLen(32, 24), NewChacha20, &Hex{}},
	Salsa20:       {newKeyIvLen(32, 8), NewSalsa20, &Hex{}},
}

func getCryptoMethod() []CryptoMethod {
	var cryptoMethod []CryptoMethod
	for method, _ := range ciphers {
		cryptoMethod = append(cryptoMethod, method)
	}
	for method, _ := range simpleCiphers {
		cryptoMethod = append(cryptoMethod, method)
	}

	return cryptoMethod
}

func getCryptoMethodKeyIv(method CryptoMethod) (KeyIv, error) {
	if conf, ok := ciphers[method]; ok {
		return conf.KeyIv, nil
	}

	if conf, ok := simpleCiphers[method]; ok {

		return conf.KeyIv, nil
	}

	return KeyIv{}, UnsupportedError(method)
}

func NewChipher(method CryptoMethod, key, iv string, opts ...Option) (Crypto, error) {
	if conf, ok := ciphers[method]; ok {
		if err := conf.CheckLen(key, iv); err != nil {
			return nil, err
		}

		options := &Options{
			mode:      conf.mode,
			padding:   conf.padding,
			codec:     conf.codec,
			newCipher: conf.newCipher,
			keyIv:     newKeyIv(key, iv),
		}

		c := &Cipher{options}

		for _, opt := range opts {
			opt(options)
		}

		return c, nil
	}

	if conf, ok := simpleCiphers[method]; ok {

		if err := conf.CheckLen(key, iv); err != nil {
			return nil, err
		}

		options := &Options{
			codec:     conf.codec,
			newStream: conf.newStream,
			keyIv:     newKeyIv(key, iv),
		}

		c, err := newSimpleCipher(options)
		if err != nil {
			return nil, err
		}

		return c, nil
	}

	return nil, UnsupportedError(method)

}

func (c *Cipher) Encrypt(plainText string) (string, error) {
	var ciphertext []byte
	// standard
	block, err := c.options.newCipher(c.options.keyIv.Key())
	if err != nil {
		return "", err
	}
	// padding
	src, err := c.options.padding.Padding([]byte(plainText), block.BlockSize())
	// mode
	if c.options.mode != nil {
		ciphertext, err = c.options.mode.Encrypt(block, src, c.options.keyIv.Iv()) // BlockSize=16
		if err != nil {
			return "", err
		}
	}
	// format
	return c.options.codec.Encode(ciphertext), nil
}

func (c *Cipher) Decrypt(src string) (string, error) {
	var plaintext []byte
	// format
	data, err := c.options.codec.Decode(src)
	if err != nil {
		return "", err
	}
	// standard
	block, err := c.options.newCipher(c.options.keyIv.Key())
	if err != nil {
		return "", err
	}
	// mode
	if c.options.mode != nil {
		plaintext, err = c.options.mode.Decrypt(block, data, c.options.keyIv.Iv()) // BlockSize=16
		if err != nil {
			return "", err
		}
	}
	// padding
	plaintext, err = c.options.padding.UnPadding(plaintext)
	return string(plaintext), nil
}

type simpleCipher struct {
	options *Options
}

func newSimpleCipher(opts *Options) (Crypto, error) {
	return &simpleCipher{options: opts}, nil
}

func (c *simpleCipher) Encrypt(plainText string) (string, error) {

	stream, err := c.options.newStream(c.options.keyIv.Key(), c.options.keyIv.Iv())
	if err != nil {
		return "", err
	}

	dest := make([]byte, len([]byte(plainText)))
	stream.XORKeyStream(dest, []byte(plainText))
	// format
	return c.options.codec.Encode(dest), nil
}

func (c *simpleCipher) Decrypt(src string) (string, error) {
	stream, err := c.options.newStream(c.options.keyIv.Key(), c.options.keyIv.Iv())
	if err != nil {
		return "", err
	}

	data, err := c.options.codec.Decode(src)
	if err != nil {
		return "", err
	}
	dest := make([]byte, len(data))
	stream.XORKeyStream(dest, data)
	return string(dest), nil
}
