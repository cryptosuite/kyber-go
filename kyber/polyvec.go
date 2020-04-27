package kyber

type polyVec struct {
	vec []*poly
}

//compress and decompress for polyvec
func (a *polyVec) compress(r []byte) {
	var t [8]uint16
	var idx = 0
	for _, v := range a.vec {
		for j := 0; j < kyberN/8; j++ {
			for k := 0; k < 8; k++ {
				t[k] = uint16((((uint32(freeze(v.coeffs[8*j+k])) << 11) + kyberQ/2) / kyberQ) & 0x7ff)
			}

			r[idx+11*j+0] = byte(t[0] & 0xff)
			r[idx+11*j+1] = byte((t[0] >> 8) | ((t[1] & 0x1f) << 3))
			r[idx+11*j+2] = byte((t[1] >> 5) | ((t[2] & 0x03) << 6))
			r[idx+11*j+3] = byte((t[2] >> 2) & 0xff)
			r[idx+11*j+4] = byte((t[2] >> 10) | ((t[3] & 0x7f) << 1))
			r[idx+11*j+5] = byte((t[3] >> 7) | ((t[4] & 0x0f) << 4))
			r[idx+11*j+6] = byte((t[4] >> 4) | ((t[5] & 0x01) << 7))
			r[idx+11*j+7] = byte((t[5] >> 1) & 0xff)
			r[idx+11*j+8] = byte((t[5] >> 9) | ((t[6] & 0x3f) << 2))
			r[idx+11*j+9] = byte((t[6] >> 6) | ((t[7] & 0x07) << 5))
			r[idx+11*j+10] = byte((t[7] >> 3))
		}
		idx += 352
	}
}

func (a *polyVec) decompress(r []byte) {
	var idx = 0
	for _, v := range a.vec {
		for j := 0; j < kyberN/8; j++ {
			v.coeffs[8*j+0] = uint16((((uint32(r[idx+11*j+0]) | ((uint32(r[idx+11*j+1]) & 0x07) << 8)) * kyberQ) + 1024) >> 11)
			v.coeffs[8*j+1] = uint16(((((uint32(r[idx+11*j+1]) >> 3) | ((uint32(r[idx+11*j+2]) & 0x3f) << 5)) * kyberQ) + 1024) >> 11)
			v.coeffs[8*j+2] = uint16(((((uint32(r[idx+11*j+2]) >> 6) | ((uint32(r[idx+11*j+3]) & 0xff) << 2) | ((uint32(r[idx+11*j+4]) & 0x01) << 10)) * kyberQ) + 1024) >> 11)
			v.coeffs[8*j+3] = uint16(((((uint32(r[idx+11*j+4]) >> 1) | ((uint32(r[idx+11*j+5]) & 0x0f) << 7)) * kyberQ) + 1024) >> 11)
			v.coeffs[8*j+4] = uint16(((((uint32(r[idx+11*j+5]) >> 4) | ((uint32(r[idx+11*j+6]) & 0x7f) << 4)) * kyberQ) + 1024) >> 11)
			v.coeffs[8*j+5] = uint16(((((uint32(r[idx+11*j+6]) >> 7) | ((uint32(r[idx+11*j+7]) & 0xff) << 1) | ((uint32(r[idx+11*j+8]) & 0x03) << 9)) * kyberQ) + 1024) >> 11)
			v.coeffs[8*j+6] = uint16(((((uint32(r[idx+11*j+8]) >> 2) | ((uint32(r[idx+11*j+9]) & 0x1f) << 6)) * kyberQ) + 1024) >> 11)
			v.coeffs[8*j+7] = uint16(((((uint32(r[idx+11*j+9]) >> 5) | ((uint32(r[idx+11*j+10]) & 0xff) << 3)) * kyberQ) + 1024) >> 11)
		}
		idx += 352
	}
}

//to and from bytes for polyvec
func (a *polyVec) toBytes(r []byte) {
	for i, p := range a.vec {
		p.toBytes(r[i*polyBytes:])
	}
}

func (a *polyVec) fromBytes(r []byte) {
	for i, p := range a.vec {
		p.fromBytes(r[i*polyBytes:])
	}
}

//ntt and invntt for polyvec
func (a *polyVec) ntt() {
	for _, p := range a.vec {
		p.ntt()
	}
}

func (a *polyVec) invntt() {
	for _, p := range a.vec {
		p.invntt()
	}
}

//a method of poly
func (r *poly) pointwiseAcc(a, b *polyVec) {
	var t uint16
	for j := 0; j < kyberN; j++ {
		t = montgomeryReduce(4613 * uint32(b.vec[0].coeffs[j])) // 4613 = 2^{2*18} % q
		r.coeffs[j] = montgomeryReduce(uint32(a.vec[0].coeffs[j]) * uint32(t))
		for i := 1; i < len(a.vec); i++ { // len(a.vec) is kyberK, 2 3 or 4
			t = montgomeryReduce(4613 * uint32(b.vec[i].coeffs[j]))
			r.coeffs[j] += montgomeryReduce(uint32(a.vec[i].coeffs[j]) * uint32(t))
		}

		r.coeffs[j] = barrettReduce(r.coeffs[j])
	}
}

//add for polyvec
func (a *polyVec) add(b, c *polyVec) {
	for i, p := range a.vec {
		p.add(b.vec[i], c.vec[i])
	}
}
