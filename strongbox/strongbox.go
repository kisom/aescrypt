/*
	strongbox is used to authenticate and secure small messages. It
	provides an interface similar to NaCL, but uses AES-256 with
	HMAC-SHA-384 for securing messages.

	Messages should be secured using the Seal function, and recovered
	using the Open function. A box (or authenticated and encrypted
	message) will be Overhead bytes longer than the message it
	came from; this package will not obscure the length of the
	message. Keys, if they are not generated using the GenerateKey
	function, should be KeySize bytes long. The KeyIsSuitable function
	may be used to test a key is the proper length.

	The boxes used in this package are suitable for 50-year security,
	assuming the keys are not compromised.
*/
package strongbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"io"
)

const cryptKeySize = 32
const tagKeySize = 48

const VersionString = "2.0.0"

// KeySize is the number of bytes a valid key should be.
const KeySize = cryptKeySize + tagKeySize

// Overhead is the number of bytes of overhead when boxing a message.
const Overhead = aes.BlockSize + sha512.Size384

var (
	errinvalidKeySize    = fmt.Errorf("invalid key size")
	errinvalidCiphertext = fmt.Errorf("invalid ciphertext")
)

// The default source for random data is the crypto/rand package's Reader.
var PRNG = rand.Reader

type Key []byte
type nonce []byte

// GenerateKey returns a key suitable for sealing and opening boxes, and a
// boolean indicating success. If the boolean is false, the Key value must
// be discarded.
func GenerateKey() (Key, bool) {
	var key Key = make([]byte, KeySize)

	_, err := io.ReadFull(PRNG, key)
	return key, err == nil
}

func generateNonce() (nonce, error) {
	var n nonce = make([]byte, aes.BlockSize)

	_, err := io.ReadFull(PRNG, n)
	return n, err

}

func encrypt(key []byte, in []byte) (out []byte, err error) {
	var iv nonce
	if iv, err = generateNonce(); err != nil {
		return
	}

	out = make([]byte, len(in)+aes.BlockSize)
	for i := 0; i < aes.BlockSize; i++ {
		out[i] = iv[i]
		iv[i] = 0
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	ctr := cipher.NewCTR(c, out[:aes.BlockSize])
	ctr.XORKeyStream(out[aes.BlockSize:], in)
	return
}

func computeTag(key []byte, in []byte) (tag []byte) {
	h := hmac.New(sha512.New384, key)
	h.Write(in)
	return h.Sum(nil)
}

func checkTag(key, in []byte) bool {
	ctlen := len(in) - sha512.Size384
	tag := in[ctlen:]
	ct := in[:ctlen]
	actualTag := computeTag(key, ct)
	return subtle.ConstantTimeCompare(tag, actualTag) == 1
}

func decrypt(key []byte, in []byte) (out []byte, err error) {
	if len(in) < aes.BlockSize {
		return nil, errinvalidCiphertext
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	iv := in[:aes.BlockSize]
	ct := in[aes.BlockSize:]
	ctr := cipher.NewCTR(c, iv)
	out = make([]byte, len(ct))
	ctr.XORKeyStream(out, ct)
	return
}

// Seal returns an authenticated and encrypted message, and a boolean
// indicating whether the sealing operation was successful. If it returns
//true, the message was successfully sealed. The box will be Overhead
// bytes longer than the message.
func Seal(message []byte, key Key) (box []byte, ok bool) {
	if !KeyIsSuitable(key) {
		return
	}

	ct, err := encrypt(key[:cryptKeySize], message)
	if err != nil {
		return
	}
	tag := computeTag(key[cryptKeySize:], ct)
	box = append(ct, tag...)
	ok = true
	return
}

// Open authenticates and decrypts a sealed message, also returning
// whether the message was successfully opened. If this is false, the
// message must be discarded. The returned message will be Overhead
// bytes shorter than the box.
func Open(box []byte, key Key) (message []byte, ok bool) {
	if !KeyIsSuitable(key) {
		return
	} else if len(box) <= Overhead {
		return
	}

	msgLen := len(box) - sha512.Size384
	if !checkTag(key[cryptKeySize:], box) {
		return nil, false
	}
	message, err := decrypt(key[:cryptKeySize], box[:msgLen])
	ok = err == nil
	return
}

// IsKeySuitable returns true if the byte slice represents a valid
// secretbox key.
func KeyIsSuitable(key []byte) bool {
	return subtle.ConstantTimeEq(int32(len(key)), int32(KeySize)) == 1
}
