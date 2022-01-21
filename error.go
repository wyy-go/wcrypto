package wcrypto

import (
	"strconv"
)

// KeySizeError key size error
type KeySizeError int

// Error implement Error interface
func (k KeySizeError) Error() string {
	return "encrypt: invalid key size " + strconv.Itoa(int(k))
}

// IvSizeError iv size error
type IvSizeError int

// Error implement Error interface
func (i IvSizeError) Error() string {
	return "encrypt: invalid iv size " + strconv.Itoa(int(i))
}

type UnsupportedError string

// Error implement Error interface
func (s UnsupportedError) Error() string {
	return "unsupported encryption method: " + string(s)
}
