package salsa

import "math/bits"

func quarterRound(y0, y1, y2, y3 uint32) (uint32, uint32, uint32, uint32) {
	var z0, z1, z2, z3 uint32
	// z1 = y1 ^ ((y0 + y3) << 7)
	z1 = y1 ^ (bits.RotateLeft32(y0+y3, 7))
	// z2 = y2 ^ ((z1 + y0) << 9)
	z2 = y2 ^ (bits.RotateLeft32(z1+y0, 9))
	// z3 = y3 ^ ((z2 + z1) << 13)
	z3 = y3 ^ (bits.RotateLeft32(z2+z1, 13))
	// z0 = y0 ^ ((z3 + z2) << 18)
	z0 = y0 ^ (bits.RotateLeft32(z3+z2, 18))
	return z0, z1, z2, z3
}
