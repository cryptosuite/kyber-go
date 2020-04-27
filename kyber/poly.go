package kyber

import "golang.org/x/crypto/sha3"

type poly struct {
	coeffs [kyberN]uint16
}

//compress and decompress for poly
func (a *poly) compress(r []byte) {
	var t [8]uint32
	var k = 0

	for i := 0; i < kyberN; i += 8 {
		for j := 0; j < 8; j++ {
			t[j] = uint32((((freeze(a.coeffs[i+j]) << 3) + kyberQ/2) / kyberQ) & 7)
		}

		r[k] = byte(t[0] | (t[1] << 3) | (t[2] << 6))
		r[k+1] = byte((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7))
		r[k+2] = byte((t[5] >> 1) | (t[6] << 2) | (t[7] << 5))
		k += 3
	}
}

func (a *poly) decompress(r []byte) {
	var idx = 0

	for i := 0; i < kyberN; i += 8 {
		a.coeffs[i+0] = ((uint16(r[idx]&7) * kyberQ) + 4) >> 3
		a.coeffs[i+1] = (((uint16(r[idx]>>3) & 7) * kyberQ) + 4) >> 3
		a.coeffs[i+2] = (((uint16(r[idx]>>6) | (uint16(r[idx+1]<<2) & 4)) * kyberQ) + 4) >> 3
		a.coeffs[i+3] = (((uint16(r[idx+1]>>1) & 7) * kyberQ) + 4) >> 3
		a.coeffs[i+4] = (((uint16(r[idx+1]>>4) & 7) * kyberQ) + 4) >> 3
		a.coeffs[i+5] = (((uint16(r[idx+1]>>7) | (uint16(r[idx+2]<<1) & 6)) * kyberQ) + 4) >> 3
		a.coeffs[i+6] = (((uint16(r[idx+2]>>2) & 7) * kyberQ) + 4) >> 3
		a.coeffs[i+7] = (((uint16(r[idx+2] >> 5)) * kyberQ) + 4) >> 3
		idx += 3
	}
}

//to and from bytes for poly
func (a *poly) toBytes(r []byte) {
	var t [8]uint16

	for i := 0; i < kyberN/8; i++ {
		for j := 0; j < 8; j++ {
			t[j] = freeze(a.coeffs[8*i+j])
		}

		r[13*i+0] = byte(t[0] & 0xff)
		r[13*i+1] = byte((t[0] >> 8) | ((t[1] & 0x07) << 5))
		r[13*i+2] = byte((t[1] >> 3) & 0xff)
		r[13*i+3] = byte((t[1] >> 11) | ((t[2] & 0x3f) << 2))
		r[13*i+4] = byte((t[2] >> 6) | ((t[3] & 0x01) << 7))
		r[13*i+5] = byte((t[3] >> 1) & 0xff)
		r[13*i+6] = byte((t[3] >> 9) | ((t[4] & 0x0f) << 4))
		r[13*i+7] = byte((t[4] >> 4) & 0xff)
		r[13*i+8] = byte((t[4] >> 12) | ((t[5] & 0x7f) << 1))
		r[13*i+9] = byte((t[5] >> 7) | ((t[6] & 0x03) << 6))
		r[13*i+10] = byte((t[6] >> 2) & 0xff)
		r[13*i+11] = byte((t[6] >> 10) | ((t[7] & 0x1f) << 3))
		r[13*i+12] = byte(t[7] >> 5)
	}
}

func (a *poly) fromBytes(r []byte) {
	for i := 0; i < kyberN/8; i++ {
		a.coeffs[8*i+0] = uint16(r[13*i+0]) | ((uint16(r[13*i+1]) & 0x1f) << 8)
		a.coeffs[8*i+1] = (uint16(r[13*i+1]) >> 5) | (uint16(r[13*i+2]) << 3) | ((uint16(r[13*i+3]) & 0x03) << 11)
		a.coeffs[8*i+2] = (uint16(r[13*i+3]) >> 2) | ((uint16(r[13*i+4]) & 0x7f) << 6)
		a.coeffs[8*i+3] = (uint16(r[13*i+4]) >> 7) | (uint16(r[13*i+5]) << 1) | ((uint16(r[13*i+6]) & 0x0f) << 9)
		a.coeffs[8*i+4] = (uint16(r[13*i+6]) >> 4) | (uint16(r[13*i+7]) << 4) | ((uint16(r[13*i+8]) & 0x01) << 12)
		a.coeffs[8*i+5] = (uint16(r[13*i+8]) >> 1) | ((uint16(r[13*i+9]) & 0x3f) << 7)
		a.coeffs[8*i+6] = (uint16(r[13*i+9]) >> 6) | (uint16(r[13*i+10]) << 2) | ((uint16(r[13*i+11]) & 0x07) << 10)
		a.coeffs[8*i+7] = (uint16(r[13*i+11]) >> 3) | (uint16(r[13*i+12]) << 5)
	}
}

//getnoise
func (a *poly) getNoise(seed []byte, nonce byte, eta int) {
	buf := make([]byte, eta*kyberN/4)
	extSeed := make([]byte, 0, SymBytes+1)

	extSeed = append(extSeed, seed...)
	extSeed = append(extSeed, nonce)

	sha3.ShakeSum256(buf, extSeed)

	a.cbd(buf, eta)
}

//ntt and invntt for poly
func (a *poly) ntt() {
	ntt(&a.coeffs)
}

func (a *poly) invntt() {
	invntt(&a.coeffs)
}

//add and sub for poly
func (a *poly) add(b, c *poly) {
	for i := range a.coeffs {
		a.coeffs[i] = barrettReduce(b.coeffs[i] + c.coeffs[i])
	}
}

func (a *poly) sub(b, c *poly) {
	for i := range a.coeffs {
		a.coeffs[i] = barrettReduce(b.coeffs[i] + 3*kyberQ - c.coeffs[i])
	}
}

//from and to message
func (a *poly) fromMsg(msg []byte) {
	var mask uint16

	for i, v := range msg[:SymBytes] {
		for j := 0; j < 8; j++ {
			mask = -((uint16(v) >> uint(j)) & 1)
			a.coeffs[8*i+j] = mask & ((kyberQ + 1) / 2)
		}
	}
}

func (a *poly) toMsg(msg []byte) {
	var t uint16

	for i := 0; i < SymBytes; i++ {
		msg[i] = 0
		for j := 0; j < 8; j++ {
			t = (((freeze(a.coeffs[8*i+j]) << 1) + kyberQ/2) / kyberQ) & 1
			msg[i] |= byte(t << uint(j))
		}
	}
}
