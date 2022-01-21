package rsa

const (
	PKCS1 = "PKCS1"
	PKCS8 = "PKCS8"
)

const (
	MD5  = "MD5"
	SHA1 = "SHA1"
)

type Option func(*Options)

type Options struct {
	priPemFile         string
	pukPemFile         string
	format             string
	bits               int
	signatureAlgorithm string
}

func WithPrivatePemFile(path string) Option {
	return func(options *Options) {
		options.priPemFile = path
	}
}

func WithPublicPemFile(path string) Option {
	return func(options *Options) {
		options.pukPemFile = path
	}
}

func WithSignatureAlgorithm(algo string) Option {
	return func(options *Options) {
		options.signatureAlgorithm = algo
	}
}

func WithFormat(format string) Option {
	return func(options *Options) {
		options.format = format
	}
}

func WithBits(bits int) Option {
	return func(options *Options) {
		options.bits = bits
	}
}

func newOptions(opts ...Option) *Options {
	options := &Options{
		priPemFile:         "private.pem",
		pukPemFile:         "public.pem",
		format:             PKCS1,
		bits:               2048,
		signatureAlgorithm: SHA1,
	}

	for _, opt := range opts {
		opt(options)
	}

	return options
}
