package chacha

import (
	"bytes"
	"encoding/binary"
	"math/bits"
)

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

func initState(key [32]byte, count [4]byte, nonce [12]byte) []uint32 {
	var w1, w2, w3, w4 uint32
	w1 = 0x61707865
	w2 = 0x3320646e
	w3 = 0x79622d32
	w4 = 0x6b206574

	s := make([]uint32, 16)
	s[0] = w1
	s[1] = w2
	s[2] = w3
	s[3] = w4

	copy(s[4:12], bytesToWords(key[:]))
	copy(s[12:13], bytesToWords(count[:]))
	copy(s[13:16], bytesToWords(nonce[:]))

	return s
}

func bytesToWords(b []byte) []uint32 {
	w := make([]uint32, len(b)/4)
	reader := bytes.NewReader(b)

	if err := binary.Read(reader, binary.LittleEndian, w); err != nil {
		panic(err)
	}

	return w
}

func block(key [32]byte, counter [4]byte, nonce [12]byte) []uint32 {
	initState := initState(key, counter, nonce)
	state := make([]uint32, 16)
	copy(state, initState)

	for i := 0; i < 10; i++ {
		innerBlock(state)
	}

	for i := 0; i < 16; i++ {
		state[i] += initState[i]
	}

	return state
}

func innerBlock(state []uint32) {
	state[0], state[4], state[8], state[12] = quarterRound(state[0], state[4], state[8], state[12])
	state[1], state[5], state[9], state[13] = quarterRound(state[1], state[5], state[9], state[13])
	state[2], state[6], state[10], state[14] = quarterRound(state[2], state[6], state[10], state[14])
	state[3], state[7], state[11], state[15] = quarterRound(state[3], state[7], state[11], state[15])
	state[0], state[5], state[10], state[15] = quarterRound(state[0], state[5], state[10], state[15])
	state[1], state[6], state[11], state[12] = quarterRound(state[1], state[6], state[11], state[12])
	state[2], state[7], state[8], state[13] = quarterRound(state[2], state[7], state[8], state[13])
	state[3], state[4], state[9], state[14] = quarterRound(state[3], state[4], state[9], state[14])
}
