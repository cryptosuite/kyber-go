package kyber

type polyVec struct {
	vector []poly
}

func newPolyVec(pp *ParamSet) *polyVec {
	return &polyVec{vector: make([]poly, pp.paramsK)}
}

// fromBytes De-serialize vector of polynomials;
//inverse of toBytes
func (p *polyVec) fromBytes(pp *ParamSet, a []byte) error {
	if len(a) != pp.paramsPolyVectorBytes {
		return ErrInvalidLength
	}
	offset := 0
	for i := 0; i < pp.paramsK; i++ {
		err := p.vector[i].fromBytes(a[offset : offset+paramsPolyBytes])
		offset += paramsPolyBytes
		if err != nil {
			return err
		}
	}
	return nil
}

// toBytes serialize vector of polynomials
func (p *polyVec) toBytes(pp *ParamSet) []byte {
	res := make([]byte, 0, pp.paramsPolyVectorBytes)
	for i := 0; i < pp.paramsK; i++ {
		res = append(res, p.vector[i].toBytes()...)
	}
	return res
}

// compress compresses and serializes vector of polynomials
func (p *polyVec) compress(pp *ParamSet) []byte {
	res := make([]byte, pp.paramsPolyVectorCompressedBytes)
	switch pp.paramsPolyVectorCompressedBytes {
	case pp.paramsK * 352:
		offset := 0
		var t [8]uint16
		for i := 0; i < pp.paramsK; i++ {
			for j := 0; j < paramsN/8; j++ {
				for k := 0; k < 8; k++ {
					t[k] = uint16(p.vector[i].coeffs[8*j+k])
					t[k] += uint16((int16(t[k]) >> 15) & paramsQ)
					t[k] = uint16((((uint32(t[k]) << 11) + paramsQ/2) / paramsQ) & 0x7FF)
				}
				res[offset+0] = byte(t[0] >> 0)
				res[offset+1] = byte((t[0] >> 8) | (t[1] << 3))
				res[offset+2] = byte((t[1] >> 5) | (t[2] << 6))
				res[offset+3] = byte(t[2] >> 2)
				res[offset+4] = byte((t[2] >> 10) | (t[3] << 1))
				res[offset+5] = byte((t[3] >> 7) | (t[4] << 4))
				res[offset+6] = byte((t[4] >> 4) | (t[5] << 7))
				res[offset+7] = byte(t[5] >> 1)
				res[offset+8] = byte((t[5] >> 9) | (t[6] << 2))
				res[offset+9] = byte((t[6] >> 6) | (t[7] << 5))
				res[offset+10] = byte(t[7] >> 3)
				offset += 11
			}
		}
	case pp.paramsK * 320:
		offset := 0
		var t [4]uint16
		for i := 0; i < pp.paramsK; i++ {
			for j := 0; j < paramsN/4; j++ {
				for k := 0; k < 4; k++ {
					t[k] = uint16(p.vector[i].coeffs[4*j+k])
					t[k] += uint16((int16(t[k]) >> 15) & paramsQ)
					t[k] = uint16((((uint32(t[k]) << 10) + paramsQ/2) / paramsQ) & 0x3FF)
				}
				res[offset+0] = byte(t[0] >> 0)
				res[offset+1] = byte((t[0] >> 8) | (t[1] << 2))
				res[offset+2] = byte((t[1] >> 6) | (t[2] << 4))
				res[offset+3] = byte((t[2] >> 4) | (t[3] << 6))
				res[offset+4] = byte(t[3] >> 2)
				offset += 5
			}
		}
	}

	return res
}

// decompress de-serializes and decompresses vector of polynomials;
//approximate inverse of compress
func (p *polyVec) decompress(pp *ParamSet, a []byte) error {
	if len(a) != pp.paramsPolyVectorCompressedBytes {
		return ErrInvalidLength
	}
	switch pp.paramsPolyVectorCompressedBytes {
	case pp.paramsK * 352:
		offset := 0
		var t [8]uint16
		for i := 0; i < pp.paramsK; i++ {
			for j := 0; j < paramsN/8; j++ {
				t[0] = uint16(a[offset+0]>>0) | (uint16(a[offset+1]) << 8)
				t[1] = uint16(a[offset+1]>>3) | (uint16(a[offset+2]) << 5)
				t[2] = uint16(a[offset+2]>>6) | (uint16(a[offset+3]) << 2) | (uint16(a[offset+4]) << 10)
				t[3] = uint16(a[offset+4]>>1) | (uint16(a[offset+5]) << 7)
				t[4] = uint16(a[offset+5]>>4) | (uint16(a[offset+6]) << 4)
				t[5] = uint16(a[offset+6]>>7) | (uint16(a[offset+7]) << 1) | (uint16(a[offset+8]) << 9)
				t[6] = uint16(a[offset+8]>>2) | (uint16(a[offset+9]) << 6)
				t[7] = uint16(a[offset+9]>>5) | (uint16(a[offset+10]) << 3)
				offset += 11
				for k := 0; k < 8; k++ {
					p.vector[i].coeffs[8*j+k] = int16(((uint32)(t[k]&0x7FF)*uint32(paramsQ) + 1024) >> 11)
				}
			}
		}
	case pp.paramsK * 320:
		offset := 0
		var t [4]uint16
		for i := 0; i < pp.paramsK; i++ {
			for j := 0; j < paramsN/4; j++ {
				t[0] = uint16(a[offset+0]>>0) | (uint16(a[offset+1]) << 8)
				t[1] = uint16(a[offset+1]>>2) | (uint16(a[offset+2]) << 6)
				t[2] = uint16(a[offset+2]>>4) | (uint16(a[offset+3]) << 4)
				t[3] = uint16(a[offset+3]>>6) | (uint16(a[offset+4]) << 2)
				offset += 5
				for k := 0; k < 4; k++ {
					p.vector[i].coeffs[4*j+k] = int16(((uint32)(t[k]&0x3FF)*uint32(paramsQ) + 512) >> 10)
				}
			}
		}
	}
	return nil
}

// ntt applies forward NTT to all elements of a vector of polynomials
func (p *polyVec) ntt(pp *ParamSet) {
	for i := 0; i < pp.paramsK; i++ {
		p.vector[i].ntt()
	}
}

// invntt applies inverse NTT to all elements of a vector of polynomials
//and multiply by Montgomery factor 2^16
func (p *polyVec) invntt(pp *ParamSet) {
	for i := 0; i < pp.paramsK; i++ {
		p.vector[i].invntt()
	}
}

//reduce applies Barrett reduction to each coefficient of each element
//of a vector of polynomials;
func (p *polyVec) reduce(pp *ParamSet) {
	for i := 0; i < pp.paramsK; i++ {
		p.vector[i].reduce()
	}
}

//add applies Barrett reduction to each coefficient of each element
//of a vector of polynomials;
func (p *polyVec) add(pp *ParamSet, a *polyVec) *polyVec {
	res := newPolyVec(pp)
	for i := 0; i < pp.paramsK; i++ {
		copy(res.vector[i].coeffs[:], p.vector[i].add(&a.vector[i]).coeffs[:])
	}
	return res
}

// baseMulACCMontgomery multiplies elements of a and u in NTT domain, and multiply by 2^-16.
func baseMulACCMontgomery(pp *ParamSet, a, b *polyVec) *poly {
	res := a.vector[0].baseMulMontgomery(&b.vector[0])
	res.reduce()
	for i := 1; i < pp.paramsK; i++ {
		tmp := a.vector[i].baseMulMontgomery(&b.vector[i])
		res = res.add(tmp)
		res.reduce()
	}
	return res
}
