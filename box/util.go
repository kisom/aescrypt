package box

import (
	"bytes"
	"encoding/binary"
	"math/big"
)

func marshalSignature(r, s *big.Int) []byte {
	sig := newbw()
	sig.Write(r.Bytes())
	sig.Write(s.Bytes())
	return sig.Bytes()
}

type bw struct {
	buf *bytes.Buffer
	err error
}

func newbw() *bw {
	b := new(bw)
	b.buf = new(bytes.Buffer)
	return b
}

func (b *bw) Write(data []byte) {
	if b.err != nil {
		return
	}
	b.err = binary.Write(b.buf, binary.BigEndian, uint32(len(data)))
	b.buf.Write(data)
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
		data := make([]byte, dlen)
		b.buf.Read(data)
		return data
	}
	return nil
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


