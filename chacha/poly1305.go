package chacha

import (
	"bytes"
	"math/big"
)

func poly1305Mac(msg []byte, key [32]byte) []byte {
	r := key[0:16]
	s := key[16:32]
	clamp(r)

	// Big int is non-performatic _and_ vulnerable to side attacks, but it is easier to deal than handle []uint64.
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

func poly1305KeyGen(key [32]byte, nonce [12]byte) []byte {
	var counter uint32
	block := block(key, counter, nonce)
	stream := wordsToBytes(block)

	return stream[0:32]
}

func padding(msg []byte) []byte {
	i := len(msg) % 16

	if i == 0 {
		return nil
	}

	return bytes.Repeat([]byte{0x00}, 16-i)
}
