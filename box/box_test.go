package box

import "bytes"
import "crypto/rand"
import "fmt"
import "io/ioutil"
import "math/big"
import "testing"

var testMessages = []string{
	"Hello, world.",
	"Yes... yes. This is a fertile land, and we will thrive. We will rule over all this land, and we will call it... This Land.",
	"Ah! Curse your sudden but inevitable betrayal!",
	"And I'm thinkin' you weren't burdened with an overabundance of schooling. So why don't we just ignore each other until we go away?",
	"Sir, I think you have a problem with your brain being missing.",
	"It's the way of life in my findings that journeys end when and where they want to; and that's where you make your home.",
	"I get confused. I remember everything. I remember too much. And... some of it's made up, and... some of it can't be quantified, and... there's secrets... and...",
	"Yeah, we're pretty much just giving each other significant glances and laughing incessantly.",
	"Jayne, go play with your rainstick.",
}

var (
	testBoxes   = make([]string, len(testMessages))
	testBoxFile []byte
	testGoodKey = PrivateKey{
		0x17, 0xa0, 0x63, 0x3d, 0xfa, 0xef, 0x1b, 0x86,
		0x4d, 0xc1, 0x9c, 0x09, 0xe0, 0xeb, 0xd8, 0xfa,
		0x3d, 0x72, 0x68, 0xc0, 0x49, 0xf2, 0x08, 0x05,
		0x75, 0xe2, 0x57, 0x86, 0xec, 0x2a, 0xf6, 0x93,
	}
	testGoodPub = PublicKey{
		0x04, 0x47, 0x10, 0x32, 0x8b, 0x3d, 0xb7, 0x7c,
		0x81, 0xb1, 0x33, 0x6e, 0xed, 0x21, 0x40, 0x75,
		0x1b, 0x44, 0x54, 0x9f, 0xdc, 0x19, 0xf0, 0x7c,
		0xdc, 0x46, 0x7a, 0xb1, 0x19, 0x07, 0x13, 0x78,
		0x20, 0x3e, 0x1e, 0x1e, 0xeb, 0xbd, 0xc8, 0x31,
		0x74, 0x1a, 0x23, 0xfc, 0xcc, 0x08, 0x6f, 0x5f,
		0xba, 0xb7, 0xa1, 0x24, 0x22, 0xa3, 0xc1, 0xd1,
		0x14, 0x2a, 0x55, 0x69, 0xf8, 0x0f, 0x25, 0xed,
		0x94,
	}
	testPeerKey = PrivateKey{
		0xcc, 0xbf, 0x0c, 0x08, 0x72, 0x2a, 0xc7, 0xf0,
		0xd2, 0xef, 0x6c, 0x06, 0xef, 0x7c, 0x7d, 0x6a,
		0xba, 0x0b, 0xb4, 0xe0, 0xc6, 0xd2, 0x88, 0x19,
		0xa4, 0x6d, 0x32, 0xa1, 0x3a, 0x10, 0x0c, 0xe4,
	}
	testPeerPub = PublicKey{
		0x04, 0x1e, 0x1e, 0x75, 0xe7, 0xbc, 0x75, 0x9b,
		0xa8, 0x4c, 0x3c, 0x09, 0x15, 0x9d, 0x09, 0x55,
		0x35, 0x7e, 0x7f, 0x45, 0xa9, 0xef, 0x55, 0xd2,
		0x65, 0xd1, 0x84, 0xba, 0x9c, 0x53, 0x03, 0x25,
		0x5a, 0xa9, 0xe0, 0x07, 0xfb, 0x3f, 0xb3, 0x5f,
		0x6d, 0xf7, 0xcc, 0xf5, 0x0f, 0x8a, 0x9e, 0xf8,
		0x5e, 0x5f, 0x30, 0xd2, 0xfd, 0x3d, 0xf6, 0x0d,
		0x7d, 0x01, 0x82, 0xdc, 0xba, 0x51, 0x19, 0x12,
		0x13,
	}
	testBadKey = PrivateKey{
		0xa8, 0xa7, 0x23, 0xa7, 0x18, 0x47, 0x5a, 0x4a,
		0x52, 0xb9, 0xf8, 0x77, 0x10, 0x66, 0x9e, 0xe7,
		0x0c, 0x28, 0x03, 0xfb, 0x90, 0x73, 0x6e, 0x9d,
		0xcf, 0x40, 0xdf, 0xba, 0x80, 0x22, 0x79, 0xcf,
	}
	testBadPub = PublicKey{
		0x04, 0x86, 0xa4, 0x50, 0x1a, 0x00, 0x1b, 0x00,
		0x11, 0xac, 0x0b, 0xed, 0x9f, 0x5b, 0x7d, 0xd6,
		0xa7, 0x82, 0x88, 0xb8, 0x42, 0xd9, 0x8f, 0x03,
		0x0a, 0x4a, 0xab, 0x90, 0x0c, 0x93, 0x05, 0xce,
		0xf2, 0x9c, 0x62, 0x0d, 0xd5, 0x8e, 0xff, 0x49,
		0x9a, 0x7a, 0xea, 0xbf, 0x49, 0xaf, 0x6f, 0xa0,
		0x02, 0x67, 0x69, 0xe8, 0x38, 0x30, 0x11, 0xde,
		0xa4, 0x0e, 0xf9, 0xaa, 0x3b, 0xc4, 0x8a, 0x5c,
		0x9d,
	}
)

func randInt(max int64) int64 {
	maxBig := big.NewInt(max)
	n, err := rand.Int(PRNG, maxBig)
	if err != nil {
		return -1
	}
	return n.Int64()
}

func mutate(in []byte) (out []byte) {
	out = make([]byte, len(in))
	copy(out, in)

	iterations := (randInt(int64(len(out))) / 2) + 1
	if iterations == -1 {
		panic("mutate failed")
	}
	for i := 0; i < int(iterations); i++ {
		mByte := randInt(int64(len(out)))
		mBit := randInt(7)
		if mBit == -1 || mByte == -1 {
			panic("mutate failed")
		}
		out[mByte] ^= (1 << uint(mBit))
	}
	if bytes.Equal(out, in) {
		panic("mutate failed")
	}
	return out
}

/*
func TestKeyGeneration(t *testing.T) {
	var ok bool
	testGoodKey, testGoodPub, ok = GenerateKey()
	if !ok {
		fmt.Println("Key generation failed")
		t.FailNow()
	}
	testPeerKey, testPeerPub, ok = GenerateKey()
	if !ok {
		fmt.Println("Key generation failed")
		t.FailNow()
	}
	testBadKey, testBadPub, ok = GenerateKey()
	if !ok {
		fmt.Println("Key generation failed")
		t.FailNow()
	}
	ioutil.WriteFile("testvectors/good.key", testGoodKey, 0644)
	ioutil.WriteFile("testvectors/good.pub", testGoodPub, 0644)
	ioutil.WriteFile("testvectors/peer.key", testPeerKey, 0644)
	ioutil.WriteFile("testvectors/peer.pub", testPeerPub, 0644)
	ioutil.WriteFile("testvectors/bad.key", testBadKey, 0644)
	ioutil.WriteFile("testvectors/bad.pub", testBadPub, 0644)
}
*/

func TestBoxing(t *testing.T) {
	for i := 0; i < len(testMessages); i++ {
		box, ok := Seal([]byte(testMessages[i]), testPeerPub)
		if !ok {
			fmt.Println("Boxing failed: message", i)
			t.FailNow()
		} else if len(box) != len(testMessages[i])+Overhead {
			fmt.Println("The box length is invalid.")
			t.FailNow()
		} else if BoxIsSigned(box) {
			fmt.Println("IsBoxSigned should return false.")
			t.FailNow()
		}
		/*
			fileName := fmt.Sprintf("testvectors/test_vector-%d.bin", i+1)
			ioutil.WriteFile(fileName, []byte(testMessages[i]), 0644)
			fileName = fmt.Sprintf("testvectors/test_box-%d.bin", i+1)
			ioutil.WriteFile(fileName, box, 0644)
		*/
		testBoxes[i] = string(box)
	}
}

func TestUnboxing(t *testing.T) {
	for i := 0; i < len(testMessages); i++ {
		message, ok := Open([]byte(testBoxes[i]), testPeerKey)
		if !ok {
			fmt.Println("Unboxing failed: message", i)
			t.FailNow()
		} else if string(message) != testMessages[i] {
			fmt.Printf("Unboxing failed: expected '%s', got '%s'\n",
				testMessages[i], string(message))
			t.FailNow()
		}
	}
}

func TestBadUnboxing(t *testing.T) {
	for i := 0; i < len(testMessages); i++ {
		_, ok := Open([]byte(testBoxes[i]), testBadKey)
		if ok {
			fmt.Println("Unboxing should have failed: message", i)
			t.FailNow()
		}
		_, ok = Open(mutate([]byte(testBoxes[i])), testGoodKey)
		if ok {
			fmt.Println("Unboxing should have failed: message", i)
			t.FailNow()
		}
	}
}

func TestSignedBoxing(t *testing.T) {
	for i := 0; i < len(testMessages); i++ {
		box, ok := SignAndSeal([]byte(testMessages[i]), testGoodKey, testGoodPub, testPeerPub)
		if !ok {
			fmt.Println("Boxing failed: message", i)
			t.FailNow()
		} else if len(box) < len(testMessages[i])+Overhead+sigSize {
			fmt.Println("The box length is invalid.")
			t.FailNow()
		} else if !BoxIsSigned(box) {
			fmt.Println("IsBoxSigned should return true.")
			t.FailNow()
		}
		/*
			fileName := fmt.Sprintf("testvectors/test_signed_vector-%d.bin", i+1)
			ioutil.WriteFile(fileName, []byte(testMessages[i]), 0644)
			fileName = fmt.Sprintf("testvectors/test_signed_box-%d.bin", i+1)
			ioutil.WriteFile(fileName, box, 0644)
		*/
		testBoxes[i] = string(box)
	}
}

func TestSignedUnboxing(t *testing.T) {
	for i := 0; i < len(testMessages); i++ {
		message, ok := OpenAndVerify([]byte(testBoxes[i]), testPeerKey, testGoodPub)
		if !ok {
			fmt.Println("Unboxing failed: message", i)
			t.FailNow()
		} else if string(message) != testMessages[i] {
			fmt.Printf("Unboxing failed: expected '%s', got '%s'\n",
				testMessages[i], string(message))
			t.FailNow()
		}
	}
}

func TestSignedBadUnboxing(t *testing.T) {
	for i := 0; i < len(testMessages); i++ {
		_, ok := OpenAndVerify([]byte(testBoxes[i]), testPeerKey, testBadPub)
		if ok {
			fmt.Println("Unboxing should have failed: message", i)
			t.FailNow()
		} else if _, ok = OpenAndVerify(mutate([]byte(testBoxes[i])), testPeerKey, testGoodPub); ok {
			fmt.Println("Unboxing should have failed: message", i)
			t.FailNow()
		} else if _, ok = OpenAndVerify(mutate([]byte(testBoxes[i])), testPeerKey, testGoodPub); ok {
			fmt.Println("Unboxing should have failed: message", i)
			t.FailNow()
		}
	}
}

// TestLargerBox tests the encryption of a 4,026 byte test file.
func TestLargerBox(t *testing.T) {
	var err error
	testBoxFile, err = ioutil.ReadFile("testdata/TEST.txt")
	if err != nil {
		fmt.Println("Failed to read test data:", err.Error())
		t.FailNow()
	}

	box, ok := Seal(testBoxFile, testPeerPub)
	if !ok {
		fmt.Println("Failed to box message.")
		t.FailNow()
	}

	message, ok := Open(box, testPeerKey)
	if !ok {
		fmt.Println("Failed to unbox message.")
		t.FailNow()
	}

	if !bytes.Equal(message, testBoxFile) {
		fmt.Println("Recovered message is invalid.")
		t.FailNow()
	}
}

func TestKeySigning(t *testing.T) {
	sig, ok := SignKey(testGoodKey, testGoodPub, testPeerPub)
	if !ok {
		fmt.Println("Failed to sign key.")
		t.FailNow()
	}

	ok = VerifySignedKey(testPeerPub, testGoodPub, sig)
	if !ok {
		fmt.Println("Key signature validation failed.")
		t.FailNow()
	}

	ok = VerifySignedKey(testPeerPub, testBadPub, sig)
	if ok {
		fmt.Println("Key signature check should have failed.")
		t.FailNow()
	}

	ok = VerifySignedKey(testPeerPub, mutate(testGoodPub), sig)
	if ok {
		fmt.Println("Key signature check should have failed.")
		t.FailNow()
	}

	ok = VerifySignedKey(mutate(testPeerPub), testGoodPub, sig)
	if ok {
		fmt.Println("Key signature check should have failed.")
		t.FailNow()
	}
}

func BenchmarkUnsignedSeal(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, ok := Seal(testBoxFile, testPeerPub)
		if !ok {
			fmt.Println("Couldn't seal message: benchmark aborted.")
			b.FailNow()
		}
	}
}

func BenchmarkSignAndSeal(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, ok := SignAndSeal(testBoxFile, testGoodKey, testGoodPub, testPeerPub)
		if !ok {
			fmt.Println("Couldn't seal message: benchmark aborted.")
			b.FailNow()
		}
	}
}

// Benchmark the Open function, which retrieves a message from a box.
func BenchmarkUnsignedOpen(b *testing.B) {
	box, ok := Seal(testBoxFile, testPeerPub)
	if !ok {
		fmt.Println("Can't seal message: benchmark aborted.")
		b.FailNow()
	}
	for i := 0; i < b.N; i++ {
		_, ok := Open(box, testPeerKey)
		if !ok {
			fmt.Println("Couldn't open message: benchmark aborted.")
			b.FailNow()
		}
	}
}

// Benchmark the Open function, which retrieves a message from a box.
func BenchmarkOpenSigned(b *testing.B) {
	box, ok := SignAndSeal(testBoxFile, testGoodKey, testGoodPub, testPeerPub)
	if !ok {
		fmt.Println("Can't seal message: benchmark aborted.")
		b.FailNow()
	}
	for i := 0; i < b.N; i++ {
		_, ok := OpenAndVerify(box, testPeerKey, testGoodPub)
		if !ok {
			fmt.Println("Couldn't open message: benchmark aborted.")
			b.FailNow()
		}
	}
}

// Benchmark the SharedKey function.
func BenchmarkSharedKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, ok := SharedKey(testGoodKey, testPeerPub)
		if !ok {
			fmt.Println("Computing shared key failed: benchmark aborted.")
			b.FailNow()
		}
	}
}

// Benchmark key signing.
func BenchmarkKeySigning(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, ok := SignKey(testGoodKey, testGoodPub, testPeerPub)
		if !ok {
			fmt.Println("Key signing failed: benchmark aborted.")
			b.FailNow()
		}
	}
}

// Benchmark key signature verification.
func BenchmarkKeyVerification(b *testing.B) {
	sig, ok := SignKey(testGoodKey, testGoodPub, testPeerPub)
	if !ok {
		fmt.Println("Key signing failed: benchmark aborted.")
		b.FailNow()
	}
	for i := 0; i < b.N; i++ {
		ok = VerifySignedKey(testPeerPub, testGoodPub, sig)
		if !ok {
			fmt.Println("Key signature verification failed: benchmark aborted.")
			b.FailNow()
		}
	}
}

/*
func TestSharedKeyPairs(t *testing.T) {
	for i := 0; i < 4; i++ {
		p_priv, p_pub, ok := GenerateKey()
		if !ok {
			fmt.Println("Failed to generate peer key.")
			t.FailNow()
		}
		privFN := fmt.Sprintf("testvectors/peer_%d.key", i)
		pubFN := fmt.Sprintf("testvectors/peer_%d.pub", i)
		ioutil.WriteFile(privFN, p_priv, 0644)
		ioutil.WriteFile(pubFN, p_pub, 0644)
	}
}
*/

var peerPublicList = []PublicKey{
	PublicKey{
		0x04, 0x52, 0xd6, 0xaf, 0xe0, 0x86, 0xf4, 0xf3,
		0xd2, 0x68, 0x4a, 0xab, 0x65, 0xad, 0x5a, 0xce,
		0xb8, 0xba, 0xba, 0x52, 0x1e, 0x3b, 0x71, 0x4e,
		0xc6, 0xd3, 0x90, 0xa5, 0x89, 0x8b, 0xf0, 0x55,
		0xea, 0xa7, 0x4c, 0x8e, 0xb6, 0xd7, 0xb0, 0x6d,
		0x28, 0x83, 0x67, 0x20, 0xa6, 0x32, 0xd9, 0xb5,
		0x1f, 0x32, 0x08, 0xe9, 0x28, 0x86, 0x93, 0x05,
		0x82, 0xd1, 0x20, 0x77, 0x53, 0x54, 0x9d, 0xee,
		0xf1,
	},
	PublicKey{
		0x04, 0x1d, 0xc0, 0x72, 0x5f, 0xd0, 0xcc, 0x54,
		0xfe, 0xa2, 0xaa, 0x49, 0x43, 0xce, 0x4e, 0xb9,
		0xce, 0xd0, 0x21, 0xa9, 0x4c, 0x75, 0x60, 0x6b,
		0xc7, 0xf3, 0x74, 0xb4, 0xa8, 0xb7, 0x89, 0x79,
		0x49, 0x29, 0xc1, 0x51, 0xc8, 0xab, 0x83, 0x88,
		0x9b, 0x57, 0xcf, 0xd8, 0x72, 0x5b, 0xd1, 0x9f,
		0x03, 0x6d, 0xb1, 0x0a, 0x8e, 0x0c, 0x57, 0xf6,
		0x22, 0x14, 0xe9, 0xd2, 0xa9, 0xdf, 0x02, 0xdc,
		0xf6,
	},
	PublicKey{
		0x04, 0x1b, 0x81, 0x55, 0x66, 0x8e, 0x73, 0xa2,
		0xd9, 0x07, 0xa1, 0xa7, 0xa0, 0xdc, 0xf3, 0xad,
		0x85, 0xfc, 0xb5, 0xc6, 0xd5, 0x60, 0x5f, 0x3e,
		0xef, 0xcc, 0x2f, 0x1f, 0xbb, 0xd4, 0x1e, 0x59,
		0x9d, 0xce, 0xf2, 0x8d, 0x6d, 0x6d, 0xed, 0x6d,
		0xd0, 0x55, 0x11, 0x20, 0x77, 0x79, 0xb6, 0x17,
		0x5a, 0x99, 0xb0, 0xf6, 0x89, 0x8a, 0x83, 0x51,
		0xf9, 0xcd, 0x51, 0x6f, 0xcb, 0x41, 0x32, 0x61,
		0x1b,
	},
	PublicKey{
		0x04, 0xb5, 0x91, 0x50, 0xf8, 0x24, 0xf3, 0xe3,
		0x81, 0xb2, 0x63, 0xda, 0x19, 0xf1, 0x7b, 0x7f,
		0x84, 0x83, 0x8b, 0xe9, 0x32, 0x5b, 0x11, 0xa9,
		0xb6, 0xf4, 0xa3, 0x25, 0x34, 0xc9, 0xf1, 0x0b,
		0x3e, 0x24, 0x6d, 0x2b, 0x9c, 0xa6, 0x34, 0x75,
		0x8e, 0x66, 0x8b, 0xfc, 0x9b, 0xb6, 0x37, 0x2b,
		0x10, 0xc0, 0xb5, 0x59, 0x6e, 0x5d, 0x53, 0xb5,
		0x00, 0xc1, 0xde, 0xf5, 0xfb, 0x16, 0x91, 0x0c,
		0xb4,
	},
}

var peerPrivList = []PrivateKey{
	PrivateKey{
		0x49, 0xe8, 0x9b, 0xa2, 0x65, 0x51, 0x51, 0x8a,
		0xe5, 0xcb, 0xab, 0xfb, 0x0f, 0xe7, 0xa5, 0x9c,
		0xea, 0x07, 0xbc, 0x39, 0x92, 0x3e, 0x09, 0x8e,
		0xe7, 0x3d, 0x80, 0x19, 0xa6, 0xc4, 0x7e, 0x31,
	},
	PrivateKey{
		0x6a, 0x28, 0xdb, 0x54, 0x09, 0x7f, 0xf4, 0x96,
		0xe9, 0x21, 0x29, 0x4d, 0xee, 0xd9, 0x1b, 0xca,
		0x43, 0xef, 0x55, 0x41, 0xae, 0xd3, 0xe1, 0xcf,
		0x2a, 0xca, 0x69, 0xae, 0xd2, 0x16, 0x4c, 0xad,
	},
	PrivateKey{
		0xdd, 0x5a, 0x32, 0x96, 0xff, 0x8d, 0x0c, 0xfd,
		0xc4, 0x4b, 0x54, 0x17, 0x89, 0x87, 0xe0, 0xdf,
		0xa6, 0x02, 0x81, 0x48, 0x47, 0xa6, 0x04, 0x0f,
		0xb2, 0xad, 0xc1, 0x7b, 0xce, 0x41, 0x7d, 0xd6,
	},
	PrivateKey{
		0x2d, 0xe4, 0x7f, 0xe0, 0xd5, 0xc6, 0xe4, 0xc4,
		0xcb, 0x63, 0x60, 0xc5, 0xe3, 0xc6, 0x60, 0xf2,
		0xd1, 0x0a, 0xf9, 0xe5, 0xff, 0xb4, 0xfc, 0x44,
		0x6a, 0x62, 0x25, 0x41, 0x5b, 0x79, 0x88, 0x1e,
	},
}

func TestSharedBoxing(t *testing.T) {
	for i := 0; i < len(testMessages); i++ {
		box, ok := SealShared([]byte(testMessages[i]), peerPublicList)
		if !ok {
			fmt.Println("Shared boxing failed: message", i)
			t.FailNow()
		}
		testBoxes[i] = string(box)
		/*
			fname := fmt.Sprintf("testvectors/test_shared_box_%d.bin", i)
			ioutil.WriteFile(fname, []byte(testBoxes[i]), 0644)
		*/
	}
}

func TestSharedUnboxing(t *testing.T) {
	for i := 0; i < len(testMessages); i++ {
		for kn := 0; kn < 4; kn++ {
			m, ok := OpenShared([]byte(testBoxes[i]),
				peerPrivList[kn],
				peerPublicList[kn])
			if !ok {
				fmt.Println("Shared unboxing failed: message", i)
				fmt.Printf("box: %x\n", testBoxes[i])
				t.FailNow()
			} else if string(m) != testMessages[i] {
				fmt.Println("Shared unboxing did not return same plaintext.")
				t.FailNow()
			}
			_, ok = OpenShared([]byte(testBoxes[i]),
				testPeerKey, testPeerPub)
			if ok {
				fmt.Println("Shared unboxing should have failed!")
				t.FailNow()
			}
		}
		_, ok := OpenShared(mutate([]byte(testBoxes[i])),
			peerPrivList[0], peerPublicList[0])
		if ok {
			fmt.Println("Unboxing should have failed: message", i)
			t.FailNow()
		}
	}
}

func TestSharedSignedBoxing(t *testing.T) {
	for i := 0; i < len(testMessages); i++ {
		box, ok := SignAndSealShared([]byte(testMessages[i]), peerPublicList, testGoodKey,
			testGoodPub)
		if !ok {
			fmt.Println("Shared boxing failed: message", i)
			t.FailNow()
		}
		testBoxes[i] = string(box)
		/*
			fname := fmt.Sprintf("testvectors/test_shared_signed_box_%d.bin", i)
			ioutil.WriteFile(fname, []byte(testBoxes[i]), 0644)
		*/
	}
}

func TestSharedSignedUnboxing(t *testing.T) {
	for i := 0; i < len(testMessages); i++ {
		for kn := 0; kn < 4; kn++ {
			m, ok := OpenSharedAndVerify([]byte(testBoxes[i]),
				peerPrivList[kn],
				peerPublicList[kn],
				testGoodPub)
			if !ok {
				fmt.Println("Shared unboxing failed: message", i)
				fmt.Printf("box: %x\n", testBoxes[i])
				t.FailNow()
			} else if string(m) != testMessages[i] {
				fmt.Println("Shared unboxing did not return same plaintext.")
				t.FailNow()
			}
			_, ok = OpenSharedAndVerify([]byte(testBoxes[i]),
				testPeerKey, testPeerPub, testGoodPub)
			if ok {
				fmt.Println("Shared unboxing should have failed!")
				t.FailNow()
			}
			_, ok = OpenSharedAndVerify([]byte(testBoxes[i]),
				peerPrivList[kn],
				peerPublicList[kn],
				testPeerPub)
			if ok {
				fmt.Println("Signature verification should have failed!")
				t.FailNow()
			}
		}
		_, ok := OpenSharedAndVerify(mutate([]byte(testBoxes[i])),
			peerPrivList[0],
			peerPublicList[0],
			testGoodPub)
		if ok {
			fmt.Println("Signature verification should have failed!")
			t.FailNow()
		}
	}
}

func BenchmarkSharedUnsignedSeal(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, ok := SealShared(testBoxFile, peerPublicList)
		if !ok {
			fmt.Println("Couldn't seal message: benchmark aborted.")
			b.FailNow()
		}
	}
}

func BenchmarkSharedSignAndSeal(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, ok := SignAndSealShared(testBoxFile, peerPublicList, testGoodKey,
			testGoodPub)
		if !ok {
			fmt.Println("Couldn't seal message: benchmark aborted.")
			b.FailNow()
		}
	}
}

// Benchmark the Open function, which retrieves a message from a box.
func BenchmarkSharedUnsignedOpen(b *testing.B) {
	box, ok := SealShared(testBoxFile, peerPublicList)
	if !ok {
		fmt.Println("Can't seal message: benchmark aborted.")
		b.FailNow()
	}
	for i := 0; i < b.N; i++ {
		_, ok := OpenShared(box, peerPrivList[3], peerPublicList[3])
		if !ok {
			fmt.Println("Couldn't open message: benchmark aborted.")
			b.FailNow()
		}
	}
}

// Benchmark the OpenSigned function, which retrieves a message from a box and verifies a
// signature on it.
func BenchmarkOpenSharedSigned(b *testing.B) {
	box, ok := SignAndSealShared(testBoxFile, peerPublicList, testGoodKey, testGoodPub)
	if !ok {
		fmt.Println("Can't seal message: benchmark aborted.")
		b.FailNow()
	}
	for i := 0; i < b.N; i++ {
		_, ok := OpenSharedAndVerify(box, peerPrivList[3], peerPublicList[3], testGoodPub)
		if !ok {
			fmt.Println("Couldn't open message: benchmark aborted.")
			b.FailNow()
		}
	}
}
