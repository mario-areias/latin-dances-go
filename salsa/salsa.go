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

func rowRound(y []uint32) {
	y[0], y[1], y[2], y[3] = quarterRound(y[0], y[1], y[2], y[3])
	y[5], y[6], y[7], y[4] = quarterRound(y[5], y[6], y[7], y[4])
	y[10], y[11], y[8], y[9] = quarterRound(y[10], y[11], y[8], y[9])
	y[15], y[12], y[13], y[14] = quarterRound(y[15], y[12], y[13], y[14])
}

func columnRound(x []uint32) {
	x[0], x[4], x[8], x[12] = quarterRound(x[0], x[4], x[8], x[12])
	x[5], x[9], x[13], x[1] = quarterRound(x[5], x[9], x[13], x[1])
	x[10], x[14], x[2], x[6] = quarterRound(x[10], x[14], x[2], x[6])
	x[15], x[3], x[7], x[11] = quarterRound(x[15], x[3], x[7], x[11])
}

func doubleRound(x []uint32) {
	columnRound(x)
	rowRound(x)
}

func littleEndian(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
