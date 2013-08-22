package box

import "bytes"
import "fmt"
import "io/ioutil"
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
		0x77, 0xd6, 0xd2, 0x6e, 0x6e, 0x7d, 0x87, 0x36,
		0xf1, 0xa9, 0x90, 0x9c, 0x02, 0x9d, 0x9e, 0xdb,
		0xad, 0x54, 0xe8, 0x67, 0xd0, 0x0a, 0x06, 0x2f,
		0xb6, 0x53, 0xb1, 0x99, 0xad, 0x2f, 0x4b, 0xfa,
	}
	testGoodPub = PublicKey{
		0x04, 0x83, 0x33, 0xc8, 0x56, 0xd5, 0x39,
		0xdc, 0x9b, 0xe6, 0x93, 0x15, 0x54, 0x67, 0xcb,
		0x09, 0x7f, 0x88, 0xf5, 0x29, 0xc5, 0x70, 0x49,
		0x4a, 0x50, 0xa0, 0x4e, 0xc2, 0x48, 0x06, 0x45,
		0xe6, 0x16, 0x25, 0x1a, 0x9c, 0x9f, 0xc6, 0x5a,
		0xc8, 0x9a, 0x77, 0x86, 0xdd, 0xb5, 0x26, 0xc7,
		0x4f, 0xf9, 0x4e, 0x37, 0x7e, 0x2e, 0xa4, 0x37,
		0xb6, 0xb3, 0x5d, 0x70, 0x64, 0xde, 0x37, 0x3a,
		0xbe, 0xba,
	}
	testPeerKey = PrivateKey{
		0x1c, 0x98, 0x25, 0xab, 0x6d, 0x77, 0xa0, 0x41,
		0x9d, 0xc0, 0xb5, 0xcd, 0x40, 0xf2, 0x03, 0xcb,
		0x6b, 0x91, 0xbe, 0x50, 0xc1, 0xe4, 0x82, 0xb1,
		0x2d, 0xe7, 0x07, 0x73, 0xaa, 0x03, 0x56, 0x3b,
	}
	testPeerPub = PublicKey{
		0x04, 0x77, 0xf8, 0xc1, 0xd0, 0x7e, 0x63,
		0x11, 0x9d, 0x2b, 0xa2, 0x56, 0x98, 0xed, 0x8a,
		0x1e, 0x02, 0xd0, 0x92, 0x6b, 0x8b, 0x59, 0xdb,
		0x9b, 0xc2, 0x87, 0xb8, 0xfb, 0x5d, 0xae, 0xc3,
		0x22, 0x89, 0xe5, 0xa4, 0xba, 0x52, 0xa3, 0xf8,
		0xe8, 0x0b, 0x4b, 0x46, 0x68, 0x40, 0x89, 0x11,
		0x95, 0xe8, 0xa7, 0x6e, 0xe7, 0x96, 0x97, 0x69,
		0x1d, 0x63, 0xde, 0x93, 0xe8, 0xa6, 0xf6, 0xb0,
		0x27, 0xa3,
	}
	testBadKey = PrivateKey{
		0xa6, 0xea, 0x12, 0xfb, 0xe4, 0x5a, 0x81, 0x50,
		0x99, 0x13, 0x70, 0xa2, 0xe4, 0x04, 0x43, 0xd8,
		0x48, 0x97, 0x31, 0xde, 0x6e, 0x22, 0x7d, 0x67,
		0xbf, 0x73, 0x54, 0x99, 0x31, 0x10, 0x95, 0xf4,
	}
	testBadPub = PublicKey{
		0x04, 0x8b, 0x30, 0x68, 0xdb, 0xa3, 0xcc,
		0xdb, 0xe7, 0x3c, 0xe5, 0x5a, 0x7c, 0x9d, 0x80,
		0x70, 0x80, 0x8b, 0x37, 0x50, 0x87, 0x3c, 0x0a,
		0x0a, 0x11, 0x38, 0x29, 0x17, 0x40, 0x9b, 0x81,
		0x13, 0x11, 0x28, 0x57, 0xcb, 0xcd, 0x80, 0x1a,
		0x75, 0x35, 0xd4, 0xa1, 0x2e, 0x66, 0x59, 0xce,
		0x64, 0xfb, 0x11, 0xed, 0xfa, 0x5d, 0xbe, 0xa2,
		0x6e, 0x6c, 0x11, 0x0e, 0x66, 0xa1, 0xc7, 0x39,
		0x2b, 0xbb,
	}
)

/*
func TestKeyGeneration(t *testing.T) {
	var ok bool
	testGoodKey, testGoodPub, ok = GenerateKey()
	if !ok {
		fmt.Println("key generation failed")
		t.FailNow()
	}
	testPeerKey, testPeerPub, ok = GenerateKey()
	if !ok {
		fmt.Println("key generation failed")
		t.FailNow()
	}
	testBadKey, testBadPub, ok = GenerateKey()
	if !ok {
		fmt.Println("key generation failed")
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
	}
}

func TestSignedBoxing(t *testing.T) {
	for i := 0; i < len(testMessages); i++ {
		box, ok := SignAndSeal([]byte(testMessages[i]), testGoodKey, testGoodPub, testPeerPub)
		if !ok {
			fmt.Println("Boxing failed: message", i)
			t.FailNow()
		} else if len(box) != len(testMessages[i])+Overhead+sigSize {
			fmt.Println("The box length is invalid.")
			t.FailNow()
		}
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
