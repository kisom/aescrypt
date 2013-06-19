package cryptokit

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
	testGoodKey PrivateKey
	testGoodPub PublicKey
	testPeerKey PrivateKey
	testPeerPub PublicKey
	testBadKey  PrivateKey
	testBadPub  PublicKey
)

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
}

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
