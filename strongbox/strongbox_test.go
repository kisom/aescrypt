package strongbox

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
	testGoodKey Key
	testBadKey  Key
)

// TestKeyGeneration generates a pair of keys, verifying that the key
// generation code works properly.
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
}

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
