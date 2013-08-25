package stoutbox

import (
	"bytes"
	"encoding/binary"
	"math/big"
)

const u32Len uint32 = 4

func marshalSignature(r, s *big.Int) []byte {
	sig := newbw(nil)
	sig.Write(r.Bytes())
	sig.Write(s.Bytes())
	return sig.Bytes()
}

type bw struct {
	buf *bytes.Buffer
	err error
}

func newbw(init []byte) *bw {
	b := new(bw)
	b.buf = new(bytes.Buffer)
	if init != nil {
		b.buf.Write(init)
	}
	return b
}

func (b *bw) Write(data []byte) {
	if b.err != nil {
		return
	}
	b.err = binary.Write(b.buf, binary.BigEndian, uint32(len(data)))
	b.buf.Write(data)
}

func (b *bw) WriteUint32(n uint32) {
	if b.err != nil {
		return
	}
	b.err = binary.Write(b.buf, binary.BigEndian, u32Len)
	if b.err == nil {
		b.err = binary.Write(b.buf, binary.BigEndian, n)
	}
}

func (b *bw) Bytes() []byte {
	if b.err != nil {
		return nil
	}
	return b.buf.Bytes()
}

func unmarshalSignature(sig []byte) (r, s *big.Int) {
	b := newbr(sig)
	rb := b.Next()
	sb := b.Next()
	if rb != nil && sb != nil {
		r = new(big.Int).SetBytes(rb)
		s = new(big.Int).SetBytes(sb)
	}
	return
}

type br struct {
	buf *bytes.Buffer
	err error
}

func newbr(data []byte) *br {
	b := new(br)
	b.buf = bytes.NewBuffer(data)
	return b
}

func (b *br) Next() []byte {
	if b.err != nil {
		return nil
	}

	var dlen uint32
	b.err = binary.Read(b.buf, binary.BigEndian, &dlen)
	if b.err == nil {
		if int(dlen) > b.buf.Len() {
			return nil
		}
		data := make([]byte, dlen)
		b.buf.Read(data)
		return data
	}
	return nil
}

func (b *br) NextU32() (uint32, bool) {
	if b.err != nil {
		return 0, false
	}

	var n uint32
	b.err = binary.Read(b.buf, binary.BigEndian, &n)
	if b.err != nil {
		return 0, false
	}
	if int(n) > b.buf.Len() {
		return 0, false
	}
	b.err = binary.Read(b.buf, binary.BigEndian, &n)
	return n, b.err == nil
}

// Zero out a byte slice.
func zero(in []byte) {
	if in == nil {
		return
	}
	inlen := len(in)
	for i := 0; i < inlen; i++ {
		in[i] ^= in[i]
	}
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
