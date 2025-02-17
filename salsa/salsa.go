package salsa

import (
	"math/bits"
)

func Encrypt(key *[32]byte, nonce, message []byte) []byte {
	if len(nonce) != 8 {
		panic("nonce must be 8 bytes")
	}

	counter := make([]byte, 8)
	output := make([]byte, len(message))

	for i := 0; i < len(message); i += 64 {
		state := initState(key[:], append(nonce, counter...))
		block := hash(state)
		for j := 0; j < len(block) && i+j < len(message); j++ {
			output[i+j] = message[i+j] ^ block[j]
		}

		incrementByteArray(counter)
	}

	return output
}

// copy from go.crypto/salsa
func incrementByteArray(byteArray []byte) {
	u := uint32(1)
	for i := 0; i < len(byteArray); i++ {
		u += uint32(byteArray[i])
		byteArray[i] = byte(u)
		u >>= 8
	}
}

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

func hash(input []byte) []byte {
	// transform bytes in words
	x := make([]uint32, 16)
	for i := 0; i < 16; i++ {
		x[i] = littleEndian(input[i*4 : i*4+4])
	}

	// calculate 10 double rounds
	z := make([]uint32, 16)
	copy(z, x)
	for i := 0; i < 10; i++ {
		doubleRound(z)
	}

	// concatenate the result
	for i := 0; i < 16; i++ {
		z[i] += x[i]
	}

	// transform words in bytes
	output := make([]byte, 64)
	for i := 0; i < 16; i++ {
		output[i*4] = byte(z[i])
		output[i*4+1] = byte(z[i] >> 8)
		output[i*4+2] = byte(z[i] >> 16)
		output[i*4+3] = byte(z[i] >> 24)
	}

	return output
}

func initState(key, nonce []byte) []byte {
	state := make([]byte, 64)
	copy(state[0:4], []byte{101, 120, 112, 97})
	copy(state[4:20], key[0:16])
	copy(state[20:24], []byte{110, 100, 32, 51})
	copy(state[24:40], nonce)
	copy(state[40:44], []byte{50, 45, 98, 121})
	copy(state[44:60], key[16:])
	copy(state[60:64], []byte{116, 101, 32, 107})
	return state
}
