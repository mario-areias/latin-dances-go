package chacha

import "math/bits"

func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 16)

	c += d
	b ^= c
	b = bits.RotateLeft32(b, 12)

	a += b
	d ^= a
	d = bits.RotateLeft32(d, 8)

	c += d
	b ^= c
	b = bits.RotateLeft32(b, 7)

	return a, b, c, d
}
func initState(key, nonce []byte) []byte {
	state := make([]byte, 64)
	copy(state[0:4], []byte{101, 120, 112, 97})
	copy(state[4:8], []byte{110, 100, 32, 51})
	copy(state[8:12], []byte{50, 45, 98, 121})
	copy(state[12:16], []byte{116, 101, 32, 107})
	copy(state[16:48], key)
	copy(state[48:64], nonce)
	return state
}
