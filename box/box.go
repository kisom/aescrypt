/*
	box is used to authenticate and secure messages using public-key
	cryptography. It provides an interface similar to NaCL, but uses
	ECIES using ephemeral ECDH for shared keys, and secret box for
	securing messages.

	Messages should be secured using the Seal function, and recovered
	using the Open function. A box (or authenticated and encrypted
	message) will be Overhead bytes longer than the message it
	came from; this package will not obscure the length of the
	message. Keys, if they are not generated using the GenerateKey
	function, should be KeySize bytes long. The KeyIsSuitable function
	may be used to test a key is the proper length.

	This package also provides signed boxes: these digitally sign the
	message before sealing them, and the signature can be checked
	on opening. These must be opened with the OpenSigned function,
	and use ECDSA for signatures.

	The boxes used in this package are suitable for 20-year security.
*/
package box

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"github.com/gokyle/cryptobox/secretbox"
	"math/big"
)

type PublicKey []byte
type PrivateKey []byte

const (
	publicKeySize  = 65
	privateKeySize = 32
	sigSize        = 64
)

const (
	SharedKeySize  = 48
	ecdhSharedSize = 32
)

// Overhead is the number of bytes of overhead when boxing a message.
var Overhead = publicKeySize + secretbox.Overhead

// SignedOverhead is the number of bytes of overhead when signing and
// boxing a message.
var SignedOverhead = publicKeySize + secretbox.Overhead + sigSize

// The default source for random data is the crypto/rand package's Reader.
var PRNG = rand.Reader

var curve = elliptic.P256()

// ecdh performs the ECDH key agreement method to generate a shared key
// between a pair of keys.
func ecdh(key PrivateKey, peer PublicKey) ([]byte, bool) {
	x, y := elliptic.Unmarshal(curve, peer)
	if x == nil {
		return nil, false
	}
	x, _ = curve.ScalarMult(x, y, key)
	if x == nil {
		return nil, false
	}
	xb := zeroPad(x.Bytes(), ecdhSharedSize)

	skey := xb[:16]
	mkey := xb[16:]
	h := sha256.New()
	h.Write(mkey)
	mkey = h.Sum(nil)

	return append(skey, mkey...), true
}

// GenerateKey generates an appropriate private and public keypair for
// use in box.
func GenerateKey() (PrivateKey, PublicKey, bool) {
	key, x, y, err := elliptic.GenerateKey(curve, PRNG)
	if err != nil {
		return nil, nil, false
	}
	peer := elliptic.Marshal(curve, x, y)
	if peer == nil {
	}
	if len(key) != privateKeySize || len(peer) != publicKeySize {
		return nil, nil, false
	}
	return key, peer, true
}

// Seal returns an authenticated and encrypted message, and a boolean
// indicating whether the sealing operation was successful. If it returns
// true, the message was successfully sealed. The box will be Overhead
// bytes longer than the message. These boxes are not dependent on having
// a private key.
func Seal(message []byte, peer PublicKey) (box []byte, ok bool) {
	if !KeyIsSuitable(nil, peer) {
		return
	}

	eph_key, eph_peer, ok := GenerateKey()
	if !ok {
		return
	}

	skey, ok := ecdh(eph_key, peer)
	if !ok {
		return
	}

	sbox, ok := secretbox.Seal(message, skey)
	if !ok {
		return
	}

	box = make([]byte, publicKeySize+len(sbox))
	copy(box, eph_peer)
	copy(box[publicKeySize:], sbox)
	return box, true
}

// Open authenticates and decrypts a sealed message, also returning
// whether the message was successfully opened. If this is false, the
// message must be discarded. The returned message will be Overhead
// bytes shorter than the box.
func Open(box []byte, key PrivateKey) (message []byte, ok bool) {
	if !KeyIsSuitable(key, nil) {
		return
	}

	if len(box) < publicKeySize+secretbox.Overhead {
		return
	}

	eph_peer := box[:publicKeySize]
	shared, ok := ecdh(key, eph_peer)
	if !ok {
		return
	}

	message, ok = secretbox.Open(box[publicKeySize:], shared)
	return
}

func ecdsa_private(key PrivateKey, pub PublicKey) (skey *ecdsa.PrivateKey, ok bool) {
	x, y := elliptic.Unmarshal(curve, pub)
	if x == nil {
		return
	}

	skey = new(ecdsa.PrivateKey)
	skey.D = new(big.Int).SetBytes(key)
	skey.PublicKey.Curve = curve
	skey.X = x
	skey.Y = y
	ok = true
	return
}

func ecdsa_public(peer PublicKey) (pkey *ecdsa.PublicKey, ok bool) {
	x, y := elliptic.Unmarshal(curve, peer)
	if x == nil {
		return
	}
	pkey = &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	return pkey, true
}

func sign(message []byte, key PrivateKey, pub PublicKey) (smessage []byte, ok bool) {
	h := sha256.New()
	h.Write(message)
	hash := h.Sum(nil)

	skey, ok := ecdsa_private(key, pub)
	if !ok {
		return
	}
	r, s, err := ecdsa.Sign(PRNG, skey, hash)
	if err == nil {
		smessage = make([]byte, len(message)+64)
		copy(smessage, message)
		sig := marshalECDSASignature(r, s)
		copy(smessage[len(message):], sig)
		ok = true
	}
	return
}

func verify(smessage []byte, peer PublicKey) bool {
	if len(smessage) <= sigSize {
		return false
	}
	sigPos := len(smessage) - sigSize
	message := smessage[:sigPos]
	sig := smessage[sigPos:]
	h := sha256.New()
	h.Write(message)

	pub, ok := ecdsa_public(peer)
	if !ok {
		return false
	}
	r, s := unmarshalECDSASignature(sig)
	if r == nil {
		return false
	}
	return ecdsa.Verify(pub, h.Sum(nil), r, s)
}

func marshalECDSASignature(r, s *big.Int) []byte {
	if r == nil || s == nil {
		return make([]byte, sigSize)
	}
	sig := make([]byte, sigSize)
	rb := r.Bytes()
	rb = zeroPad(rb, 32)
	sb := s.Bytes()
	sb = zeroPad(sb, 32)
	copy(sig, rb)
	copy(sig[32:], sb)
	return sig
}

func unmarshalECDSASignature(sig []byte) (r, s *big.Int) {
	if len(sig) != sigSize {
		return
	}
	r = new(big.Int).SetBytes(sig[:32])
	s = new(big.Int).SetBytes(sig[32:])
	return
}

// SignAndSeal adds a digital signature to the message before sealing it.
func SignAndSeal(message []byte, key PrivateKey, public PublicKey, peer PublicKey) (box []byte, ok bool) {
	smessage, ok := sign(message, key, public)
	if !ok {
		return
	}
	box, ok = Seal(smessage, peer)
	return
}

// OpenSigned opens a signed box, and verifies the signature. If the box
// couldn't be opened or the signature is invalid, OpenSigned returns false,
// and the message value must be discarded.
func OpenAndVerify(box []byte, key PrivateKey, peer PublicKey) (message []byte, ok bool) {
	smessage, ok := Open(box, key)
	if !ok {
		return
	}

	ok = verify(smessage, peer)
	message = smessage[:len(smessage)-sigSize]
	return
}

// zeroPad returns a new slice of length size. The contents of input are right
// aligned in the new slice.
func zeroPad(in []byte, outlen int) (out []byte) {
	var inLen int
	if inLen = len(in); inLen > outlen {
		inLen = outlen
	} else if inLen == outlen {
		return in
	}
	start := outlen - inLen
	out = make([]byte, outlen)
	copy(out[start:], in)
	return
}

// IsKeySuitable takes a private and/or public key, and returns true if
// all keys passed in are valid. If no key is passed in, or any key passed
// in is invalid, it will return false.
func KeyIsSuitable(key PrivateKey, pub PublicKey) bool {
	if key == nil && pub == nil {
		return false
	} else if key != nil && len(key) != privateKeySize {
		return false
	} else if pub != nil && len(pub) != publicKeySize {
		return false
	}
	return true
}
