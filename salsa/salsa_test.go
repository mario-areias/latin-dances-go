package salsa

import (
	"fmt"
	"slices"
	"testing"
)

// tests taking from https://weaversa.github.io/cryptol-course/labs/Salsa20/Salsa20Spec.pdf
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
		t.Errorf("rowRound() = %s, want %s", print(y), print(expected))
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
		t.Errorf("rowRound() = %s, want %s", print(y), print(expected))
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
		t.Errorf("columnRound() = %s, want %s", print(x), print(expected))
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
		t.Errorf("columnRound() = %s, want %s", print(x), print(expected))
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
		t.Errorf("doubleRound() = %s, want %s", print(x), print(expected))
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
		t.Errorf("doubleRound() = %s, want %s", print(x), print(expected))
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

func print(x []uint32) string {
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
