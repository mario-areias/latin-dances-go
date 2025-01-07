package chacha

import "testing"

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
