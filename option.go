package wcrypto

type Options struct {
	mode      Mode
	padding   Padding
	codec     Codec
	newStream NewStream
	newCipher NewCipher
	keyIv     KeyIv
}

type Option func(*Options)

func WithMode(bm BlockMode) Option {
	return func(c *Options) {
		c.mode = getModeByType(bm)
	}
}

func WithPadding(padding PaddingType) Option {
	return func(c *Options) {
		c.padding = paddings[padding]
	}
}

func WithCodec(code CodecType) Option {
	return func(c *Options) {
		c.codec = codecs[code]
	}
}
