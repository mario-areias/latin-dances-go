package chacha

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"math/bits"
)

func Encrypt(key [32]byte, nonce [12]byte, message []byte) []byte {
	counter := uint32(1)

	result := make([]byte, len(message))
	for i := 0; len(message) >= 64; i += 64 {
		end := i + 64

		copy(result[i:end], encrypt(key, nonce, counter, message[:64]))
		counter++

		message = message[64:]
	}

	if len(message) > 0 {
		i := len(result) - len(message)
		end := i + len(message)

		copy(result[i:end], encrypt(key, nonce, counter, message))
	}

	return result
}

func encrypt(key [32]byte, nonce [12]byte, counter uint32, message []byte) []byte {
	result := make([]byte, len(message))

	stream := block(key, counter, nonce)
	s := wordsToBytes(stream)

	for i, b := range message {
		result[i] = b ^ s[i]
	}

	return result
}

func wordsToBytes(w []uint32) []byte {
	writer := new(bytes.Buffer)

	// Write each uint32 to the buffer
	for _, num := range w {
		if err := binary.Write(writer, binary.LittleEndian, num); err != nil {
			panic(err)
		}
	}

	return writer.Bytes()
}

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

func initState(key [32]byte, counter uint32, nonce [12]byte) []uint32 {
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
	s[12] = counter
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

func block(key [32]byte, counter uint32, nonce [12]byte) []uint32 {
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

func poly1305Mac(msg []byte, key [32]byte) []byte {
	r := key[0:16]
	s := key[16:32]
	clamp(r)

	// Big int is non-performatic, but it is easier to deal than handle []uint64.
	var a big.Int

	sn := littleEndiaBytesToBigInt(s[:])
	// fmt.Printf("sn: %08x\n", sn.Bytes())
	rn := littleEndiaBytesToBigInt(r[:])
	// fmt.Printf("rn: %08x\n", rn.Bytes())

	p := constantPrime()

	for len(msg) >= 16 {
		block := make([]byte, 16)
		copy(block, msg[:16])

		// fmt.Printf("Accumulator: %08x\n", a.Bytes())
		// fmt.Printf("Block: %08x\n", block)

		t := append(block, 0x01)
		// fmt.Printf("Block with 0x01: %08x\n", t)

		n := littleEndiaBytesToBigInt(t)
		a.Add(&a, &n)
		// fmt.Printf("Accumulator + Block: %8x\n", a.Bytes())

		a.Mul(&a, &rn)
		// fmt.Printf("Accumulator + Block * rn: %8x\n", a.Bytes())

		a.Mod(&a, p)
		// fmt.Printf("Accumulator + Block * rn mod p: %8x\n", a.Bytes())

		msg = msg[16:]
	}

	if len(msg) > 0 {
		block := make([]byte, len(msg))
		copy(block, msg)

		// fmt.Printf("Accumulator: %08x\n", a.Bytes())
		// fmt.Printf("Block: %08x\n", block)

		t := append(block, 0x01)
		// fmt.Printf("Block with 0x01: %08x\n", t)

		n := littleEndiaBytesToBigInt(t)

		a.Add(&a, &n)
		// fmt.Printf("Accumulator + Block: %8x\n", a.Bytes())

		a.Mul(&a, &rn)
		// fmt.Printf("Accumulator + Block * rn: %8x\n", a.Bytes())

		a.Mod(&a, p)
		// fmt.Printf("Accumulator + Block * rn mod p: %8x\n", a.Bytes())
	}

	a.Add(&a, &sn)
	// fmt.Printf("Accumulator + s: %8x\n", a.Bytes())

	b := make([]byte, len(a.Bytes()))
	copy(b, a.Bytes())
	bigToLitleEndian(b)

	return b[:16]
}

func clamp(r []byte) []byte {
	r[3] &= 15
	r[7] &= 15
	r[11] &= 15
	r[15] &= 15
	r[4] &= 252
	r[8] &= 252
	r[12] &= 252

	return r
}

func uint64ToBytes(u uint64) []byte {
	buffer := new(bytes.Buffer)

	if err := binary.Write(buffer, binary.LittleEndian, u); err != nil {
		panic(err)
	}

	return buffer.Bytes()
}

func littleEndiaBytesToBigInt(b []byte) big.Int {
	// bloody go only accepts big endian bytes to add to big int.
	bigToLitleEndian(b)

	var n big.Int
	n.SetBytes(b)
	return n
}

func bigToLitleEndian(b []byte) {
	i := 0
	j := len(b) - 1

	for i < j {
		b[i], b[j] = b[j], b[i]
		i++
		j--
	}
}

func constantPrime() *big.Int {
	bigInt := new(big.Int)
	bigInt.Lsh(bigInt.SetInt64(1), 130)
	bigInt.Sub(bigInt, big.NewInt(5))

	return bigInt
}
