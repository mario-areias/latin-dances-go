package salsa

import "testing"

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
