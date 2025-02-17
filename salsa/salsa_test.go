package salsa

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"slices"
	"testing"

	"golang.org/x/crypto/salsa20"
)

// tests taking from https://cr.yp.to/snuffle/spec.pdf
func TestQuarterRound(t *testing.T) {
	x0, x1, x2, x3 := quarterRound(0x00000000, 0x00000000, 0x00000000, 0x00000000)
	if x0 != 0x00000000 || x1 != 0x00000000 || x2 != 0x00000000 || x3 != 0x00000000 {
		t.Errorf("quarterRound(0, 0, 0, 0) = %08x, %08x, %08x, %08x", x0, x1, x2, x3)
	}
	x0, x1, x2, x3 = quarterRound(0x00000001, 0x00000000, 0x00000000, 0x00000000)
	if x0 != 0x08008145 || x1 != 0x00000080 || x2 != 0x00010200 || x3 != 0x20500000 {
		t.Errorf("quarterRound(1, 0, 0, 0) = %08x, %08x, %08x, %08x", x0, x1, x2, x3)
	}
	x0, x1, x2, x3 = quarterRound(0x00000000, 0x00000001, 0x00000000, 0x00000000)
	if x0 != 0x88000100 || x1 != 0x00000001 || x2 != 0x00000200 || x3 != 0x00402000 {
		t.Errorf("quarterRound(0, 1, 0, 0) = %08x, %08x, %08x, %08x", x0, x1, x2, x3)
	}
	x0, x1, x2, x3 = quarterRound(0x00000000, 0x00000000, 0x00000001, 0x00000000)
	if x0 != 0x80040000 || x1 != 0x00000000 || x2 != 0x00000001 || x3 != 0x00002000 {
		t.Errorf("quarterRound(0, 0, 1, 0) = %08x, %08x, %08x, %08x", x0, x1, x2, x3)
	}
	x0, x1, x2, x3 = quarterRound(0x00000000, 0x00000000, 0x00000000, 0x00000001)
	if x0 != 0x00048044 || x1 != 0x00000080 || x2 != 0x00010000 || x3 != 0x20100001 {
		t.Errorf("quarterRound(0, 0, 0, 1) = %08x, %08x, %08x, %08x", x0, x1, x2, x3)
	}
	x0, x1, x2, x3 = quarterRound(0xe7e8c006, 0xc4f9417d, 0x6479b4b2, 0x68c67137)
	if x0 != 0xe876d72b || x1 != 0x9361dfd5 || x2 != 0xf1460244 || x3 != 0x948541a3 {
		t.Errorf("quarterRound(e7e8c006, c4f9417d, 6479b4b2, 68c67137) = %08x, %08x, %08x, %08x", x0, x1, x2, x3)
	}
	x0, x1, x2, x3 = quarterRound(0xd3917c5b, 0x55f1c407, 0x52a58a7a, 0x8f887a3b)
	if x0 != 0x3e2f308c || x1 != 0xd90a8f36 || x2 != 0x6ab2a923 || x3 != 0x2883524c {
		t.Errorf("quarterRound(d3917c5b, 55f1c407, 52a58a7a, 8f887a3b) = %08x, %08x, %08x, %08x", x0, x1, x2, x3)
	}
}

func TestRowRound(t *testing.T) {
	y := []uint32{0x00000001, 0x00000000, 0x00000000, 0x00000000,
		0x00000001, 0x00000000, 0x00000000, 0x00000000,
		0x00000001, 0x00000000, 0x00000000, 0x00000000,
		0x00000001, 0x00000000, 0x00000000, 0x00000000}

	rowRound(y)

	expected := []uint32{0x08008145, 0x00000080, 0x00010200, 0x20500000,
		0x20100001, 0x00048044, 0x00000080, 0x00010000,
		0x00000001, 0x00002000, 0x80040000, 0x00000000,
		0x00000001, 0x00000200, 0x00402000, 0x88000100}

	if !slices.Equal(y, expected) {
		t.Errorf("rowRound() = %s, want %s", printWords(y), printWords(expected))
	}

	y = []uint32{0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
		0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
		0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
		0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a}

	rowRound(y)

	expected = []uint32{0xa890d39d, 0x65d71596, 0xe9487daa, 0xc8ca6a86,
		0x949d2192, 0x764b7754, 0xe408d9b9, 0x7a41b4d1,
		0x3402e183, 0x3c3af432, 0x50669f96, 0xd89ef0a8,
		0x0040ede5, 0xb545fbce, 0xd257ed4f, 0x1818882d}

	if !slices.Equal(y, expected) {
		t.Errorf("rowRound() = %s, want %s", printWords(y), printWords(expected))
	}
}

func TestColumnRound(t *testing.T) {
	x := []uint32{0x00000001, 0x00000000, 0x00000000, 0x00000000,
		0x00000001, 0x00000000, 0x00000000, 0x00000000,
		0x00000001, 0x00000000, 0x00000000, 0x00000000,
		0x00000001, 0x00000000, 0x00000000, 0x00000000}

	columnRound(x)

	expected := []uint32{0x10090288, 0x00000000, 0x00000000, 0x00000000,
		0x00000101, 0x00000000, 0x00000000, 0x00000000,
		0x00020401, 0x00000000, 0x00000000, 0x00000000,
		0x40a04001, 0x00000000, 0x00000000, 0x00000000}

	if !slices.Equal(x, expected) {
		t.Errorf("columnRound() = %s, want %s", printWords(x), printWords(expected))
	}

	x = []uint32{0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
		0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
		0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
		0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a}

	columnRound(x)

	expected = []uint32{0x8c9d190a, 0xce8e4c90, 0x1ef8e9d3, 0x1326a71a,
		0x90a20123, 0xead3c4f3, 0x63a091a0, 0xf0708d69,
		0x789b010c, 0xd195a681, 0xeb7d5504, 0xa774135c,
		0x481c2027, 0x53a8e4b5, 0x4c1f89c5, 0x3f78c9c8}

	if !slices.Equal(x, expected) {
		t.Errorf("columnRound() = %s, want %s", printWords(x), printWords(expected))
	}
}

func TestDoubleRound(t *testing.T) {
	x := []uint32{0x00000001, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000}

	doubleRound(x)

	expected := []uint32{0x8186a22d, 0x0040a284, 0x82479210, 0x06929051,
		0x08000090, 0x02402200, 0x00004000, 0x00800000,
		0x00010200, 0x20400000, 0x08008104, 0x00000000,
		0x20500000, 0xa0000040, 0x0008180a, 0x612a8020}

	if !slices.Equal(x, expected) {
		t.Errorf("doubleRound() = %s, want %s", printWords(x), printWords(expected))
	}

	x = []uint32{0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57,
		0xb75540d3, 0x43e93a4c, 0x3a6f2aa0, 0x726d6b36,
		0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11,
		0x054bf545, 0x254dd653, 0xd9421b6d, 0x67b276c1,
	}

	doubleRound(x)

	expected = []uint32{0xccaaf672, 0x23d960f7, 0x9153e63a, 0xcd9a60d0,
		0x50440492, 0xf07cad19, 0xae344aa0, 0xdf4cfdfc,
		0xca531c29, 0x8e7943db, 0xac1680cd, 0xd503ca00,
		0xa74b2ad6, 0xbc331c5c, 0x1dda24c7, 0xee928277}

	if !slices.Equal(x, expected) {
		t.Errorf("doubleRound() = %s, want %s", printWords(x), printWords(expected))
	}
}

func TestLittleEndian(t *testing.T) {
	tests := []struct {
		name string

		input  []byte
		output uint32
	}{
		{
			name:   "zero",
			input:  []byte{0, 0, 0, 0},
			output: 0x00000000,
		},
		{
			name:   "random numbers",
			input:  []byte{86, 75, 30, 9},
			output: 0x091e4b56,
		},
		{
			name:   "almost max value",
			input:  []byte{255, 255, 255, 250},
			output: 0xfaffffff,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			little := littleEndian(test.input)
			if little != test.output {
				t.Errorf("littleEndian(%v) = %08x, want %08x", test.input, little, test.output)
			}
		})
	}
}

func TestHash(t *testing.T) {
	input := bytes.Repeat([]byte{0}, 64)
	expected := bytes.Repeat([]byte{0}, 64)

	output := hash(input)

	if !bytes.Equal(output, expected) {
		t.Errorf("hash() = %x, want %x", output, expected)
	}

	input = []byte{
		211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37, 191, 187, 234, 136,
		49, 237, 179, 48, 1, 106, 178, 219, 175, 199, 166, 48, 86, 16, 179, 207,
		31, 240, 32, 63, 15, 83, 93, 161, 116, 147, 48, 113, 238, 55, 204, 36,
		79, 201, 235, 79, 3, 81, 156, 47, 203, 26, 244, 243, 88, 118, 104, 54}

	expected = []byte{
		109, 42, 178, 168, 156, 240, 248, 238, 168, 196, 190, 203, 26, 110, 170, 154,
		29, 29, 150, 26, 150, 30, 235, 249, 190, 163, 251, 48, 69, 144, 51, 57,
		118, 40, 152, 157, 180, 57, 27, 94, 107, 42, 236, 35, 27, 111, 114, 114,
		219, 236, 232, 135, 111, 155, 110, 18, 24, 232, 95, 158, 179, 19, 48, 202}

	output = hash(input)

	if !bytes.Equal(output, expected) {
		t.Errorf("hash() = %x, want %x", output, expected)
	}

	input = []byte{
		88, 118, 104, 54, 79, 201, 235, 79, 3, 81, 156, 47, 203, 26, 244, 243,
		191, 187, 234, 136, 211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37,
		86, 16, 179, 207, 49, 237, 179, 48, 1, 106, 178, 219, 175, 199, 166, 48,
		238, 55, 204, 36, 31, 240, 32, 63, 15, 83, 93, 161, 116, 147, 48, 113,
	}

	expected = []byte{
		179, 19, 48, 202, 219, 236, 232, 135, 111, 155, 110, 18, 24, 232, 95, 158,
		26, 110, 170, 154, 109, 42, 178, 168, 156, 240, 248, 238, 168, 196, 190, 203,
		69, 144, 51, 57, 29, 29, 150, 26, 150, 30, 235, 249, 190, 163, 251, 48,
		27, 111, 114, 114, 118, 40, 152, 157, 180, 57, 27, 94, 107, 42, 236, 35,
	}

	output = hash(input)

	if !bytes.Equal(output, expected) {
		t.Errorf("hash() = %x, want %x", output, expected)
	}

	input = []byte{
		6, 124, 83, 146, 38, 191, 9, 50, 4, 161, 47, 222, 122, 182, 223, 185,
		75, 27, 0, 216, 16, 122, 7, 89, 162, 104, 101, 147, 213, 21, 54, 95,
		225, 253, 139, 176, 105, 132, 23, 116, 76, 41, 176, 207, 221, 34, 157, 108,
		94, 94, 99, 52, 90, 117, 91, 220, 146, 190, 239, 143, 196, 176, 130, 186,
	}

	expected = []byte{
		8, 18, 38, 199, 119, 76, 215, 67, 173, 127, 144, 162, 103, 212, 176, 217,
		192, 19, 233, 33, 159, 197, 154, 160, 128, 243, 219, 65, 171, 136, 135, 225,
		123, 11, 68, 86, 237, 82, 20, 155, 133, 189, 9, 83, 167, 116, 194, 78,
		122, 127, 195, 185, 185, 204, 188, 90, 245, 9, 183, 248, 226, 85, 245, 104,
	}

	for i := 0; i < 1000000; i++ {
		output = hash(input)
		input = output
	}

	if !bytes.Equal(output, expected) {
		t.Errorf("hash() = %x, want %x", output, expected)
	}
}

func TestInitState(t *testing.T) {
	k0 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	k1 := []byte{201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216}

	n := []byte{101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116}

	expected := []byte{
		69, 37, 68, 39, 41, 15, 107, 193, 255, 139, 122, 6, 170, 233, 217, 98,
		89, 144, 182, 106, 21, 51, 200, 65, 239, 49, 222, 34, 215, 114, 40, 126,
		104, 197, 7, 225, 197, 153, 31, 2, 102, 78, 76, 176, 84, 245, 246, 184,
		177, 160, 133, 130, 6, 72, 149, 119, 192, 195, 132, 236, 234, 103, 246, 74,
	}

	ouput := hash(initState(append(k0, k1...), n))

	if !bytes.Equal(ouput, expected) {
		t.Errorf("initState() = %x, want %x", ouput, expected)
	}
}

func TestEncrypt(t *testing.T) {
	plaintext := "Trying to create a big plain text so it can test encryption with multiple blocks"

	key := [32]byte{}
	nonce := [8]byte{}

	// Generate random key and nonce
	if _, err := rand.Read(key[:]); err != nil {
		panic(err)
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		panic(err)
	}

	// check if my implementation and Go's implementation encrypt the same
	out := Encrypt(&key, nonce[:], []byte(plaintext))
	stdout := stdSalsa(&key, nonce[:], []byte(plaintext))
	if !bytes.Equal(out, stdout) {
		t.Errorf("Encrypt() = %x, want %x", out, stdout)
	}

	// decrypt the message with my implementation and Go's implementation
	p := Encrypt(&key, nonce[:], out)
	if string(p) != plaintext {
		t.Errorf("Decrypt() = %s, want %s", p, plaintext)
	}

	// decrypt the message with Go's implementation
	p = stdSalsa(&key, nonce[:], out)
	if string(p) != plaintext {
		t.Errorf("stdSalsa() = %s, want %s", p, plaintext)
	}
}

func stdSalsa(key *[32]byte, nonce, message []byte) []byte {
	out := make([]byte, len(message))

	salsa20.XORKeyStream(out, message, nonce, key)

	return out
}

func printWords(x []uint32) string {
	s := "\n"
	for i := 0; i < len(x); i++ {
		s += fmt.Sprintf("%08x, ", x[i])
		if (i+1)%4 == 0 {
			s += "\n"
		}
	}

	s += "\n"
	return s
}
