package strongbox

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
	testGoodKey = Key{
		0x7c, 0xde, 0x21, 0xcf, 0x13, 0x1d, 0x45, 0x40,
		0x81, 0x16, 0xda, 0x93, 0xe0, 0x04, 0x78, 0x0d,
		0x71, 0x16, 0x15, 0x4c, 0x80, 0x02, 0x9b, 0x20,
		0x7c, 0xb4, 0x31, 0x50, 0x5b, 0xf9, 0x25, 0x1a,
		0x71, 0x01, 0x43, 0xc1, 0x0d, 0xc9, 0xc7, 0x04,
		0xf6, 0xb9, 0x26, 0x80, 0xde, 0xd2, 0xc5, 0x78,
		0xd9, 0x7d, 0x66, 0xd2, 0x3b, 0x7a, 0x20, 0xd0,
		0xdc, 0x90, 0xa0, 0x30, 0x43, 0x8a, 0x45, 0x82,
		0x9f, 0x08, 0x16, 0x96, 0xd4, 0x24, 0x1d, 0xd3,
		0xea, 0x2a, 0x92, 0x4c, 0x8b, 0x89, 0xad, 0xb6,
	}
	testBadKey = Key{
		0xe1, 0x56, 0xea, 0x9d, 0x67, 0x90, 0xe2, 0x68,
		0xb3, 0x83, 0x5c, 0x1e, 0x02, 0x62, 0xc7, 0x06,
		0xcb, 0xee, 0xf7, 0x18, 0xd3, 0x7c, 0x41, 0x40,
		0xf8, 0xcc, 0x34, 0xfd, 0xcc, 0xfd, 0x21, 0x0b,
		0x31, 0xee, 0x82, 0xc4, 0x71, 0xa4, 0xb9, 0xeb,
		0xef, 0xed, 0x8c, 0x84, 0xc7, 0xcd, 0x17, 0xc9,
		0x76, 0xf2, 0x57, 0xe5, 0x63, 0x3c, 0x0e, 0xe4,
		0xdb, 0x54, 0x3f, 0xb3, 0xd3, 0x97, 0xf9, 0xf1,
		0x9d, 0x36, 0xc9, 0xbf, 0x58, 0xd8, 0x15, 0x56,
		0x07, 0xe6, 0x1e, 0xcf, 0x51, 0xb4, 0xde, 0xe8,
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

// TestKeyGeneration generates a pair of keys, verifying that the key
// generation code works properly.
/*
func TestKeyGeneration(t *testing.T) {
	var err error
	testGoodKey, err = GenerateKey()
	if err != nil {
		fmt.Println("Failed to generate key:", err.Error())
		t.FailNow()
	}
	testBadKey, err = GenerateKey()
	if err != nil {
		fmt.Println("Failed to generate key:", err.Error())
		t.FailNow()
	}
	    ioutil.WriteFile("testvectors/good.key", testGoodKey, 0644)
	    ioutil.WriteFile("testvectors/bad.key", testBadKey, 0644)
}
*/

/*
func TestBasicUnbox(t *testing.T) {
	testMessage := []byte{1, 2, 3, 4, 5}
	testKey := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
	box, ok := Seal(testMessage, testKey)
	if !ok {
		fmt.Println("[+] basic unboxing failed!")
		t.FailNow()
	}
}
*/

// TestBoxing ensures that sealing a message into a box works properly.
func TestBoxing(t *testing.T) {
	for i := 0; i < len(testMessages); i++ {
		box, ok := Seal([]byte(testMessages[i]), testGoodKey)
		if !ok {
			fmt.Println("Boxing failed: message", i)
			t.FailNow()
		} else if len(box) != len(testMessages[i])+Overhead {
			fmt.Println("The box length is invalid.")
			t.FailNow()
		}
		testBoxes[i] = string(box)
	}
}

// TestUnboxing ensures that unsealing (or opening) a box to retrieve
// a message works properly.
func TestUnboxing(t *testing.T) {
	for i := 0; i < len(testMessages); i++ {
		message, ok := Open([]byte(testBoxes[i]), testGoodKey)
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

// TestUnboxingFails ensures that attempting to retrieve a message from
// a box with the wrong key will fail.
func TestUnboxingFails(t *testing.T) {
	for i := 0; i < len(testMessages); i++ {
		_, ok := Open([]byte(testBoxes[i]), testBadKey)
		if ok {
			fmt.Println("Unboxing should have failed with bad key:", i)
			t.FailNow()
		}
		_, ok = Open(mutate([]byte(testBoxes[i])), testGoodKey)
		if ok {
			fmt.Println("Modified message should have failed:", i)
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

	box, ok := Seal(testBoxFile, testGoodKey)
	if !ok {
		fmt.Println("Failed to box message.")
		t.FailNow()
	}

	message, ok := Open(box, testGoodKey)
	if !ok {
		fmt.Println("Failed to unbox message.")
		t.FailNow()
	}

	if !bytes.Equal(message, testBoxFile) {
		fmt.Println("Recovered message is invalid.")
		t.FailNow()
	}
}

// Benchmark the Seal function, which secures the message.
func BenchmarkSeal(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, ok := Seal(testBoxFile, testGoodKey)
		if !ok {
			fmt.Println("Couldn't seal message: benchmark aborted.")
			b.FailNow()
		}
	}
}

// Benchmark the Open function, which retrieves a message from a box.
func BenchmarkOpen(b *testing.B) {
	box, ok := Seal(testBoxFile, testGoodKey)
	if !ok {
		fmt.Println("Can't seal message: benchmark aborted.")
		b.FailNow()
	}
	for i := 0; i < b.N; i++ {
		_, ok := Open(box, testGoodKey)
		if !ok {
			fmt.Println("Couldn't open message: benchmark aborted.")
			b.FailNow()
		}
	}
}
