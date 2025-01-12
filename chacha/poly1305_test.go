package chacha

import (
	"fmt"
	"slices"
	"testing"
)

func TestPoly1305Mac(t *testing.T) {
	// 85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:0
	// 3:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b
	key := [32]byte{0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
		0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
		0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
		0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b}

	msg := "Cryptographic Forum Research Group"

	expected := []byte{0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9}

	tag := poly1305Mac([]byte(msg), key)

	if !slices.Equal(tag, expected) {
		t.Errorf("Poly1305Mac tag: expected %s, tag %s", printBytes(expected), printBytes(tag))
	}
}

func TestPoly1305KeyGen(t *testing.T) {
	key := [32]byte{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
		0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f}

	nonce := [12]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}

	// 8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71
	// a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46
	expected := [32]byte{0x8a, 0xd5, 0xa0, 0x8b, 0x90, 0x5f, 0x81, 0xcc,
		0x81, 0x50, 0x40, 0x27, 0x4a, 0xb2, 0x94, 0x71,
		0xa8, 0x33, 0xb6, 0x37, 0xe3, 0xfd, 0x0d, 0xa5,
		0x08, 0xdb, 0xb8, 0xe2, 0xfd, 0xd1, 0xa6, 0x46}

	out := poly1305KeyGen(key, nonce)

	if !slices.Equal(out, expected[:]) {
		t.Errorf("Poly1305KeyGen: expected %s, got %s", printBytes(expected[:]), printBytes(out))
	}
}

func printBytes(b []byte) string {
	s := ""
	for i := 0; i < len(b); i++ {
		s += fmt.Sprintf("%x ", b[i])
		if (i+1)%16 == 0 {
			s += "\n"
		}
	}
	s += "\n"
	return s
}
