package kyber

import "errors"

var (
	zetas = [128]int16{
		-1044, -758, -359, -1517, 1493, 1422, 287, 202,
		-171, 622, 1577, 182, 962, -1202, -1474, 1468,
		573, -1325, 264, 383, -829, 1458, -1602, -130,
		-681, 1017, 732, 608, -1542, 411, -205, -1571,
		1223, 652, -552, 1015, -1293, 1491, -282, -1544,
		516, -8, -320, -666, -1618, -1162, 126, 1469,
		-853, -90, -271, 830, 107, -1421, -247, -951,
		-398, 961, -1508, -725, 448, -1065, 677, -1275,
		-1103, 430, 555, 843, -1251, 871, 1550, 105,
		422, 587, 177, -235, -291, -460, 1574, 1653,
		-246, 778, 1159, -147, -777, 1483, -602, 1119,
		-1590, 644, -872, 349, 418, 329, -156, -75,
		817, 1097, 603, 610, 1322, -1285, -1465, 384,
		-1215, -136, 1218, -1335, -874, 220, -1187, -1659,
		-1185, -1530, -1278, 794, -1510, -854, -870, 478,
		-108, -308, 996, 991, 958, -1460, 1522, 1628,
	}
)

var (
	ErrInvalidLength = errors.New("invalid length of input bytes")
	//ErrParamterValue = errors.New("unsupported parameter")
)

type poly struct {
	coeffs [paramsN]int16
}

// getNoiseETA1 sample a polynomial deterministically from a seed and a nonce, with
//output polynomial close to centered binomial distribution with paramter ParamsEta1
func (p *poly) getNoiseETA1(pp *ParamSet, seed []byte, nonce uint8) error {
	if len(seed) != paramsSymBytes {
		return ErrInvalidLength
	}
	length := pp.paramsETA1 * paramsN / 4
	res := shake256PRF(length, seed, nonce)
	p.cbd(pp.paramsETA1, res)
	return nil
}

/// getNoiseETA2 sample a polynomial deterministically from a seed and a nonce, with
//output polynomial close to centered binomial distribution with paramter ParamsEta2
func (p *poly) getNoiseETA2(pp *ParamSet, seed []byte, nonce uint8) error {
	if len(seed) != paramsSymBytes {
		return ErrInvalidLength
	}
	length := pp.paramsETA1 * paramsN / 4
	res := shake256PRF(length, seed, nonce)
	p.cbd(pp.paramsETA2, res)
	return nil
}

// cbd computes polynomial with coefficients distributed according to a centered
//binomial distribution wth ParamsEta given an array of uniformly random bytes.
func (p *poly) cbd(eta int, buf []byte) {
	var t, d uint32
	var a, b int16
	switch eta {
	case 2:

		for i := 0; i < paramsN/8; i++ {
			t = load32LittleEndian(buf[4*i:])
			d = t & 0x55555555
			d += (t >> 1) & 0x55555555

			for j := 0; j < 8; j++ {
				a = int16((d >> (4 * j)) & 0x3)
				b = int16((d >> (4*j + 2)) & 0x3)
				p.coeffs[8*i+j] = a - b
			}
		}
		return
	case 3:
		for i := 0; i < paramsN/8; i++ {
			t = load24LittleEndian(buf[4*i:])
			d = t & 0x00249249
			d += (t >> 1) & 0x00249249
			d += (t >> 2) & 0x00249249

			for j := 0; j < 4; j++ {
				a = int16((d >> (6 * j)) & 0x7)
				b = int16((d >> (6*j + 3)) & 0x7)
				p.coeffs[4*i+j] = a - b
			}
		}
		return
	default:

	}

}

// ntt computes legacy click number-theoretic transform (NTT) of a polynomial in place;
//inputs assumed to be in normal order, output in bit-reversed order
func (p *poly) ntt() {
	k := 1
	i := 0
	for length := 128; length >= 2; length >>= 1 {
		for start := 0; start < 256; start = i + length {
			zeta := zetas[k]
			k++
			for i = start; i < start+length; i++ {
				t := fqmul(zeta, p.coeffs[i+length])
				p.coeffs[i+length] = p.coeffs[i] - t
				p.coeffs[i] = p.coeffs[i] + t
			}
		}
	}
	p.reduce()
}

// invntt in-place inverses number-theoretic transform in Rq and multiplication
//by Montgomery factor 2^16. And input must be in bit-reversed order, output is
//standard order.
func (p *poly) invntt() {
	const f int16 = 1441 // MONT^2/128
	k := 127
	var i int
	for length := 2; length <= 128; length <<= 1 {
		for start := 0; start < 256; start = i + length {
			zeta := zetas[k]
			k--
			for i = start; i < start+length; i++ {
				t := p.coeffs[i]
				p.coeffs[i] = barrettReduce(t + p.coeffs[i+length])
				p.coeffs[i+length] = p.coeffs[i+length] - t
				p.coeffs[i+length] = fqmul(zeta, p.coeffs[i+length])
			}
		}
	}
	for i := 0; i < 256; i++ {
		p.coeffs[i] = fqmul(p.coeffs[i], f)
	}
}

// fromMsg convert 32-byte message to a polynomial
func (p *poly) fromMsg(msg []byte) error {
	if len(msg) > paramsINDCPAMsgBytes {
		return ErrInvalidLength
	} else {
		for len(msg) < paramsINDCPAMsgBytes {
			msg = append(msg, 0)
		}
	}
	var mask int16
	for i := 0; i < paramsN/8; i++ {
		for j := 0; j < 8; j++ {
			mask = -(int16(msg[i]>>j) & 1)
			p.coeffs[8*i+j] = mask & ((paramsQ + 1) / 2)
		}
	}
	return nil
}

// toMsg convert a polynomial to 32-byte message
func (p *poly) toMsg() []byte {
	res := make([]byte, paramsINDCPAMsgBytes)
	var t uint16
	for i := 0; i < paramsN/8; i++ {
		for j := 0; j < 8; j++ {
			t = uint16(p.coeffs[8*i+j])
			t += uint16(int16(t>>15) & paramsQ)
			t = (((t << 1) + paramsQ/2) / paramsQ) & 1
			res[i] = res[i] | uint8(t<<j)
		}
	}
	return res
}

// fromBytes make de-serialization of a polynomial,inverse of Serialize
func (p *poly) fromBytes(a []byte) error {
	if len(a) != paramsPolyBytes {
		return ErrInvalidLength
	}
	for i := 0; i < paramsN/2; i++ {
		p.coeffs[2*i+0] = int16((uint16(a[3*i+0]>>0) | (uint16(a[3*i+1]) << 8)) & 0xFFF)
		p.coeffs[2*i+1] = int16((uint16(a[3*i+1]>>4) | (uint16(a[3*i+2]) << 4)) & 0xFFF)
	}
	return nil
}

// toBytes make serialization of a polynomial
func (p *poly) toBytes() []byte {
	res := make([]byte, paramsPolyBytes)
	var t0, t1 uint16
	for i := 0; i < paramsN/2; i++ {
		t0 = uint16(p.coeffs[2*i])
		t0 += uint16((int16(t0) >> 15) & paramsQ)
		t1 = uint16(p.coeffs[2*i+1])
		t1 += uint16((int16(t1) >> 15) & paramsQ)
		res[3*i] = byte(t0 >> 0)
		res[3*i+1] = byte((t0 >> 8) | (t1 << 4))
		res[3*i+2] = byte(t1 >> 4)
	}
	return res
}

// compress make compression and subsequent serialization of a polynomial
func (p *poly) compress(pp *ParamSet) []byte {
	var t [8]uint8
	offset := 0
	res := make([]byte, pp.paramsPolyCompressedBytes)
	switch pp.paramsPolyCompressedBytes {
	case 128:
		for i := 0; i < paramsN/8; i++ {
			// map to positive standard representatives
			for j := 0; j < 8; j++ {
				u := p.coeffs[8*i+j]
				u += (u >> 15) & paramsQ
				t[j] = uint8((((uint16(u) << 4) + paramsQ/2) / paramsQ) & 15)
			}
			res[offset+0] = t[0] | (t[1] << 4)
			res[offset+1] = t[2] | (t[3] << 4)
			res[offset+2] = t[4] | (t[5] << 4)
			res[offset+3] = t[6] | (t[7] << 4)
			offset += 4
		}
	case 160:
		for i := 0; i < paramsN/8; i++ {
			// map to positive standard representatives
			for j := 0; j < 8; j++ {
				u := p.coeffs[8*i+j]
				u += (u >> 15) & paramsQ
				t[j] = uint8((((uint32(u) << 5) + paramsQ/2) / paramsQ) & 31)
			}
			res[offset+0] = (t[0] >> 0) | (t[1] << 5)
			res[offset+1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7)
			res[offset+2] = (t[3] >> 1) | (t[4] << 4)
			res[offset+3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6)
			res[offset+4] = (t[6] >> 2) | (t[7] << 3)
			offset += 5
		}
	default:

	}
	return res
}

// decompress make de-serialization and subsequent decompression of a polynomial,
//approximately inverse of compress
func (p *poly) decompress(pp *ParamSet, a []byte) error {
	// check the length
	if len(a) != pp.paramsPolyCompressedBytes {
		return ErrInvalidLength
	}
	switch pp.paramsPolyCompressedBytes {
	case 128:
		offset := 0
		for i := 0; i < paramsN/2; i++ {
			p.coeffs[2*i+0] = int16((((uint16(a[offset+0]) & 15) * paramsQ) + 8) >> 4)
			p.coeffs[2*i+1] = int16((((uint16(a[offset+0]) >> 4) * paramsQ) + 8) >> 4)
			offset += 1
		}
	case 160:
		var t [8]uint8
		offset := 0
		for i := 0; i < paramsN/8; i++ {
			t[0] = a[offset+0] >> 0
			t[1] = (a[offset+0] >> 5) | (a[offset+1] << 3)
			t[2] = a[offset+1] >> 2
			t[3] = (a[offset+1] >> 7) | (a[offset+2] << 1)
			t[4] = (a[offset+2] >> 4) | (a[offset+3] << 4)
			t[5] = a[offset+3] >> 1
			t[6] = (a[offset+3] >> 6) | (a[offset+4] << 2)
			t[7] = a[offset+4] >> 3
			offset += 5
			for j := 0; j < 8; j++ {
				p.coeffs[8*i+j] = int16(((uint32(t[j]&31) * paramsQ) + 16) >> 5)
			}
		}
	}

	return nil
}

// toMont in-place conversion of all coefficients of a polynomial
//from normal domain to Montgomery domain
func (p *poly) toMont() {
	const f int16 = (1 << 32) % paramsQ
	for i := 0; i < paramsN; i++ {
		p.coeffs[i] = montgomeryReduce(int32(p.coeffs[i]) * int32(f))
	}
}

// reduce applies barret reduction to all coefficients of a polynomial
func (p *poly) reduce() {
	for i := 0; i < paramsN; i++ {
		p.coeffs[i] = barrettReduce(p.coeffs[i])
	}
}

// baseMulMontgomery make multiplication of two polynomials in NTT domain
func (p *poly) baseMulMontgomery(a *poly) *poly {
	res := new(poly)
	for i := 0; i < paramsN/4; i++ {
		tmp := baseMul(p.coeffs[4*i:], a.coeffs[4*i:], zetas[64+i])
		res.coeffs[4*i] = tmp[0]
		res.coeffs[4*i+1] = tmp[1]
		tmp = baseMul(p.coeffs[4*i+2:], a.coeffs[4*i+2:], -zetas[64+i])
		res.coeffs[4*i+2] = tmp[0]
		res.coeffs[4*i+3] = tmp[1]
	}
	return res
}

// add adds a polynomials; no modular reduction is performed
func (p *poly) add(a *poly) *poly {
	res := new(poly)
	for i := 0; i < paramsN; i++ {
		res.coeffs[i] = p.coeffs[i] + a.coeffs[i]
	}
	return res
}

// sub subtracts a polynomials; no modular reduction is performed
func (p *poly) sub(a *poly) *poly {
	res := new(poly)
	for i := 0; i < paramsN; i++ {
		res.coeffs[i] = p.coeffs[i] - a.coeffs[i]
	}
	return res
}
