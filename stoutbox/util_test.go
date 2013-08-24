package stoutbox

import "testing"
import "fmt"

func TestU32(t *testing.T) {
	w := newbw(nil)
	w.WriteUint32(uint32(4))

	b := w.Bytes()
	if b == nil {
		fmt.Println("Bwriter failed.")
		t.FailNow()
	}

	r := newbr(b)
	n, ok := r.NextU32()
	if !ok {
		fmt.Println("Breader failed.")
		t.FailNow()
	} else if n != 4 {
		fmt.Println("expected 4, got", n)
		t.FailNow()
	}
}
