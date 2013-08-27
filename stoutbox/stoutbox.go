/*
   stoutbox is used to authenticate and secure messages using
   public-key cryptography. It provides an interface similar to
   NaCL, but uses ECIES using ephemeral ECDH for shared keys, and
   secret box for securing messages.

   Messages should be secured using the Seal function, and recovered
   using the Open function. A box (or authenticated and encrypted
   message) will be Overhead bytes longer than the message it came
   from; this package will not obscure the length of the message.
   Keys, if they are not generated using the GenerateKey function,
   should be KeySize bytes long. The KeyIsSuitable function may be
   used to test a key is the proper length.

   This package also provides signed boxes: these digitally sign the
   message before sealing them, and the signature can be checked on
   opening. These must be opened with the OpenSigned function, and
   use ECDSA for signatures.

   The boxes used in this package are suitable for 50-year security.
*/
package stoutbox

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"github.com/gokyle/cryptobox/strongbox"
	"math/big"
)

type PublicKey []byte
type PrivateKey []byte

const VersionString = "2.0.0"
const (
	publicKeySize  = 133
	privateKeySize = 66
	sigSize        = 140
)

const (
	BoxUnsigned     byte = 1
	BoxSigned       byte = 2
	BoxShared       byte = 11
	BoxSharedSigned byte = 12
	peerList             = 21
)

const (
	SharedKeySize  = 80
	ecdhSharedSize = 80
)

// Overhead is the number of bytes of overhead when boxing a message. This will be greater
// for locked and shared boxes.
var Overhead = publicKeySize + strongbox.Overhead + 9 // 9: two four byte lengths and type

// SignedOverhead is the number of bytes of overhead when signing and
// boxing a message.
var SignedOverhead = publicKeySize + strongbox.Overhead + sigSize

// The default source for random data is the crypto/rand package's Reader.
var PRNG = rand.Reader

var curve = elliptic.P521()

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
	xb := x.Bytes()

	skey := xb[:32]
	mkey := xb[32:]
	h := sha512.New384()
	h.Write(mkey)
	mkey = h.Sum(nil)

	return append(skey, mkey...), true
}

// SharedKey precomputes a key for encrypting with strongbox.
func SharedKey(key PrivateKey, peer PublicKey) (strongbox.Key, bool) {
	return ecdh(key, peer)
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

func sealBox(message []byte, peer PublicKey, boxtype byte) *bw {
	if message == nil {
		return nil
	} else if !KeyIsSuitable(nil, peer) {
		return nil
	}

	eph_key, eph_peer, ok := GenerateKey()
	if !ok {
		return nil
	}
	defer zero(eph_key)

	skey, ok := ecdh(eph_key, peer)
	if !ok {
		return nil
	}
	defer zero(skey)

	packer := newbw([]byte{boxtype})
	sbox, ok := strongbox.Seal(message, skey)
	if !ok {
		return nil
	}

	packer.Write(eph_peer)
	packer.Write(sbox)
	return packer
}

// Seal returns an authenticated and encrypted message, and a boolean
// indicating whether the sealing operation was successful. If it returns
// true, the message was successfully sealed. The box will be Overhead
// bytes longer than the message. These boxes are not dependent on having
// a private key. However, if a private key is passed in sigkey (with the
// corresponding public key in sigpub), the box will be signed.
func Seal(message []byte, peer PublicKey) (box []byte, ok bool) {
	packer := sealBox(message, peer, BoxUnsigned)
	if packer == nil {
		ok = false
	} else {
		box = packer.Bytes()
		if box == nil {
			ok = false
		} else {
			ok = true
		}
	}
	return
}

func openBox(box []byte, key PrivateKey) (btype byte, message []byte, ok bool) {
	if box == nil {
		return 0, nil, false
	} else if !KeyIsSuitable(key, nil) {
		return 0, nil, false
	}
	btype = box[0]
	unpacker := newbr(box[1:])
	eph_pub := unpacker.Next()
	sbox := unpacker.Next()

	shared, ok := ecdh(key, eph_pub)
	if !ok {
		return 0, nil, false
	}

	message, ok = strongbox.Open(sbox, shared)
	if !ok {
		return 0, nil, false
	}

	return btype, message, true
}

// Open authenticates and decrypts a sealed message, also returning
// whether the message was successfully opened. If this is false, the
// message must be discarded. The returned message will be Overhead
// bytes shorter than the box.
func Open(box []byte, key PrivateKey) (message []byte, ok bool) {
	btype, message, ok := openBox(box, key)
	if !ok {
		return nil, false
	} else if message == nil {
		return nil, false
	} else if btype != BoxUnsigned {
		return nil, false
	}
	return message, true
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

// Sign is used to certify a message with the key pair passed in. It returns a
// boolean indicating success; on success, the signature value returned will
// contain the signature.
func Sign(message []byte, key PrivateKey, pub PublicKey) (signature []byte, ok bool) {
	if message == nil {
		return nil, false
	} else if !KeyIsSuitable(key, pub) {
		return nil, false
	}
	h := sha512.New384()
	h.Write(message)
	hash := h.Sum(nil)

	skey, ok := ecdsa_private(key, pub)
	if !ok {
		return
	}
	r, s, err := ecdsa.Sign(PRNG, skey, hash)
	if err != nil {
		ok = false
	} else {
		signature = marshalSignature(r, s)
		if signature == nil {
			ok = false
		}
	}
	return
}

// Verify returns true if the signature is a valid signature by the signer
// for the message. If there is a failure (include failing to verify the
// signature), Verify returns false.
func Verify(message, signature []byte, signer PublicKey) bool {
	if message == nil || signature == nil {
		return false
	} else if !KeyIsSuitable(nil, signer) {
		return false
	}
	r, s := unmarshalSignature(signature)
	if r == nil || s == nil {
		return false
	}
	h := sha512.New384()
	h.Write(message)

	pub, ok := ecdsa_public(signer)
	if !ok {
		return false
	}
	return ecdsa.Verify(pub, h.Sum(nil), r, s)
}

// SignAndSeal adds a digital signature to the message before sealing it.
func SignAndSeal(message []byte, key PrivateKey, public PublicKey, peer PublicKey) (box []byte, ok bool) {
	sig, ok := Sign(message, key, public)
	if !ok || sig == nil {
		return nil, false
	}
	mpack := newbw(nil)
	mpack.Write(message)
	mpack.Write(sig)
	signedMessage := mpack.Bytes()
	if signedMessage == nil {
		return nil, false
	}
	defer zero(signedMessage)
	packer := sealBox(signedMessage, peer, BoxSigned)
	if packer == nil {
		return nil, false
	}
	box = packer.Bytes()
	if box == nil {
		return nil, false
	}
	return box, true
}

// OpenAndVerify opens a signed box, and verifies the signature. If the box
// couldn't be opened or the signature is invalid, OpenAndVerify returns false,
// and the message value must be discarded.
func OpenAndVerify(box []byte, key PrivateKey, peer PublicKey) (message []byte, ok bool) {
	btype, smessage, ok := openBox(box, key)
	if !ok || smessage == nil {
		return nil, false
	} else if btype != BoxSigned {
		return nil, false
	}
	mpack := newbr(smessage)
	message = mpack.Next()
	if message == nil {
		return nil, false
	}
	sig := mpack.Next()
	if sig == nil {
		return nil, false
	}

	if !Verify(message, sig, peer) {
		return nil, false
	}
	return message, true
}

// BoxIsSigned returns true if the box is a signed box, and false otherwise.
func BoxIsSigned(box []byte) bool {
	if box == nil {
		return false
	} else if box[0] == BoxSigned {
		return true
	} else if box[0] == BoxSharedSigned {
		return true
	} else {
		return false
	}
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

// SignKey takes the key pair specified in priv, pub and uses that to
// sign the peer key. It returns a signature and true on success;
// if ok is false, the signature should be discarded as signing failed.
func SignKey(priv PrivateKey, pub, peer PublicKey) (sig []byte, ok bool) {
	key, ok := ecdsa_private(priv, pub)
	if !ok {
		return nil, false
	}

	h := sha512.New384()
	h.Write(peer)
	m := h.Sum(nil)
	r, s, err := ecdsa.Sign(PRNG, key, m)
	if err != nil {
		return nil, false
	}
	sig = marshalSignature(r, s)
	if sig == nil {
		return nil, false
	}
	return sig, true
}

// VerifySign checks the signature on the peer key with the sigpub
// key. It returns true if the signature is valid, or false if the
// signature is invalid or an error occurred.
func VerifySignedKey(pub, sigpub PublicKey, sig []byte) bool {
	ecpub, ok := ecdsa_public(sigpub)
	if !ok {
		return false
	}

	r, s := unmarshalSignature(sig)
	if r == nil || s == nil {
		return false
	}

	h := sha512.New384()
	h.Write(pub)
	m := h.Sum(nil)
	return ecdsa.Verify(ecpub, m, r, s)
}

func boxForPeer(e_priv PrivateKey, peer PublicKey, key strongbox.Key) ([]byte, bool) {
	shared, ok := ecdh(e_priv, peer)
	if !ok {
		return nil, false
	}
	defer zero(shared)
	return strongbox.Seal(key, shared)

}

func buildSharedBox(message []byte, peers []PublicKey, btype byte) []byte {
	if message == nil {
		return nil
	}

	for _, peer := range peers {
		if peer == nil {
			return nil
		} else if !KeyIsSuitable(nil, peer) {
			return nil
		}
	}

	e_priv, e_pub, ok := GenerateKey()
	if !ok {
		return nil
	}

	shared, ok := strongbox.GenerateKey()
	if !ok {
		return nil
	}
	defer zero(shared)

	packPeers := newbw([]byte{peerList})
	packPeers.WriteUint32(uint32(len(peers)))
	for _, peer := range peers {
		packPeers.Write(peer)
		pbox, ok := boxForPeer(e_priv, peer, shared)
		if !ok {
			return nil
		}
		packPeers.Write(pbox)
	}
	plist := packPeers.Bytes()
	if plist == nil {
		return nil
	}

	packer := newbw([]byte{btype})
	packer.Write(e_pub)
	packer.Write(plist)
	sbox, ok := strongbox.Seal(message, shared)
	if !ok {
		return nil
	}
	packer.Write(sbox)
	return packer.Bytes()
}

// SealShared returns an authenticated and encrypted message shared
// between multiple peers, and a boolean indicating whether the sealing
// operation was successful. If it returns true, the message was
// successfully sealed. These boxes are not dependent on having a private
// key.
func SealShared(message []byte, peers []PublicKey) (box []byte, ok bool) {
	box = buildSharedBox(message, peers, BoxShared)
	if box == nil {
		ok = false
	} else {
		ok = true
	}
	return box, ok
}

// SignAndSeal adds a digital signature to the shared message before
// sealing it.
func SignAndSealShared(message []byte, peers []PublicKey, sigkey PrivateKey, sigpub PublicKey) (box []byte, ok bool) {
	sig, ok := Sign(message, sigkey, sigpub)
	if !ok {
		return nil, false
	}
	mpack := newbw(nil)
	mpack.Write(message)
	mpack.Write(sig)
	signedMessage := mpack.Bytes()
	if signedMessage == nil {
		return nil, false
	}
	defer zero(signedMessage)

	box = buildSharedBox(signedMessage, peers, BoxSharedSigned)
	if box == nil {
		ok = false
	} else {
		ok = true
	}
	return box, ok
}

func unpackSharedBox(box []byte, key PrivateKey, public PublicKey) (btype byte, message []byte, ok bool) {
	if box == nil {
		return 0, nil, false
	} else if !KeyIsSuitable(key, public) {
		return 0, nil, false
	}
	btype = box[0]

	unpacker := newbr(box[1:])
	e_pub := unpacker.Next()
	if e_pub == nil {
		return 0, nil, false
	}

	packedPeers := unpacker.Next()
	if packedPeers == nil {
		return 0, nil, false
	} else if packedPeers[0] != peerList {
		return 0, nil, false
	}
	peerUnpack := newbr(packedPeers[1:])
	peerCount, ok := peerUnpack.NextU32()
	if !ok {
		return 0, nil, false
	}

	var shared []byte = nil
	defer zero(shared)

	for i := uint32(0); i < peerCount; i++ {
		peer := peerUnpack.Next()
		if peer == nil {
			return 0, nil, false
		}
		sbox := peerUnpack.Next()
		if sbox == nil {
			return 0, nil, false
		} else if !bytes.Equal(peer, public) {
			continue
		}
		skey, ok := ecdh(key, e_pub)
		if !ok {
			return 0, nil, false
		}
		shared, ok = strongbox.Open(sbox, skey)
		if !ok {
			return 0, nil, false
		}
		break
	}
	if shared == nil {
		return 0, nil, false
	}
	sbox := unpacker.Next()
	if sbox == nil {
		return 0, nil, false
	}
	message, ok = strongbox.Open(sbox, shared)
	if !ok {
	}
	return btype, message, ok
}

// OpenShared authenticates and decrypts a sealed shared message, also
// returning whether the message was successfully opened. If this is
// false, the message must be discarded.
func OpenShared(box []byte, key PrivateKey, public PublicKey) (message []byte, ok bool) {
	btype, message, ok := unpackSharedBox(box, key, public)
	if !ok {
		return nil, false
	} else if message == nil {
		return nil, false
	} else if btype != BoxShared {
		return nil, false
	}
	return message, true
}

// OpenSharedAndVerify opens a signed shared box, and verifies the
// signature. If the box couldn't be opened or the signature is invalid,
// OpenSharedAndVerify returns false, and the message value must be
// discarded.
func OpenSharedAndVerify(box []byte, key PrivateKey, public PublicKey, signer PublicKey) (message []byte, ok bool) {
	btype, smessage, ok := unpackSharedBox(box, key, public)
	if !ok {
		return nil, false
	} else if smessage == nil {
		return nil, false
	} else if btype != BoxSharedSigned {
		return nil, false
	}

	mpack := newbr(smessage)
	message = mpack.Next()
	if message == nil {
		return nil, false
	}
	sig := mpack.Next()
	if sig == nil {
		return nil, false
	}

	if !Verify(message, sig, signer) {
		return nil, false
	}
	return message, true
}
