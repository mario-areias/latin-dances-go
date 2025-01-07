package chacha

import (
	"fmt"
	"slices"
	"testing"
)

// Tests got from here https://www.rfc-editor.org/rfc/rfc8439#section-2.1
func TestQuarterRound(t *testing.T) {
	tests := []struct {
		name string

		input    [4]uint32
		expected [4]uint32
	}{
		{
			name:     "Section 2.1.1",
			input:    [4]uint32{0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567},
			expected: [4]uint32{0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb},
		},
		{
			name:     "Section 2.2.1",
			input:    [4]uint32{0x516461b1, 0x2a5f714c, 0x53372767, 0x3d631689},
			expected: [4]uint32{0xbdb886dc, 0xcfacafd2, 0xe46bea80, 0xccc07c79},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b, c, d := quarterRound(tt.input[0], tt.input[1], tt.input[2], tt.input[3])
			if a != tt.expected[0] {
				t.Errorf("Expected %x, got %x", tt.expected[0], a)
			}
			if b != tt.expected[1] {
				t.Errorf("Expected %x, got %x", tt.expected[1], b)
			}
			if c != tt.expected[2] {
				t.Errorf("Expected %x, got %x", tt.expected[2], c)
			}
			if d != tt.expected[3] {
				t.Errorf("Expected %x, got %x", tt.expected[3], d)
			}
		})
	}
}

func TestBlock(t *testing.T) {
	key := [32]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}

	nonce := [12]byte{0x00, 0x00, 0x00, 0x09, 0x00, 0x00,
		0x00, 0x4a, 0x00, 0x00, 0x00, 0x00}

	// little endian 1
	count := [4]byte{0x01, 0x00, 0x00, 0x00}

	// just init state
	expectedInit := [16]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
		0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
		0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
		0x00000001, 0x09000000, 0x4a000000, 0x00000000}

	init := initState(key, count, nonce)

	if !slices.Equal(init, expectedInit[:]) {
		t.Errorf("Init state: Expected %s, got %s", printWords(expectedInit[:]), printWords(init))
	}

	// after 10 rounds of innerBlock
	expectedRounds := [16]uint32{0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f,
		0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7,
		0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd,
		0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2}

	for i := 0; i < 10; i++ {
		innerBlock(init)
	}

	if !slices.Equal(init, expectedRounds[:]) {
		t.Errorf("InnerBlock: Expected %s, got %s", printWords(expectedRounds[:]), printWords(init))
	}

	// now the whole thing
	b := block(key, count, nonce)

	expectedBlock := [16]uint32{0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
		0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
		0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
		0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2}

	if !slices.Equal(b, expectedBlock[:]) {
		t.Errorf("Block: Expected %s, got %s", printWords(expectedBlock[:]), printWords(b))
	}
}

func printWords(w []uint32) string {
	s := "\n"
	for i := 0; i < 16; i++ {
		s += fmt.Sprintf("0%x ", w[i])
		if (i+1)%4 == 0 {
			s += "\n"
		}
	}

	s += "\n"
	return s
}
