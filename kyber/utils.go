package kyber

import (
	"crypto/rand"
	"golang.org/x/crypto/sha3"
)

func shake256PRF(length int, key []byte, nonce uint8) []byte {
	hash := make([]byte, length)
	sha3.ShakeSum256(hash, append(key, nonce))
	return hash
}

func load32LittleEndian(x []byte) uint32 {
	var r uint32
	r = uint32(x[0])
	r |= uint32(x[1]) << 8
	r |= uint32(x[2]) << 16
	r |= uint32(x[3]) << 24
	return r
}
func load24LittleEndian(x []byte) uint32 {
	var r uint32
	r = uint32(x[0])
	r |= uint32(x[1]) << 8
	r |= uint32(x[2]) << 16
	return r
}

func fqmul(a int16, b int16) int16 {
	return montgomeryReduce(int32(a) * int32(b))
}
func montgomeryReduce(a int32) int16 {
	var t int32
	var u int16
	const QINV = -3327
	u = int16(a) * int16(QINV)
	t = int32(u) * int32(paramsQ)
	t = a - t
	t >>= 16
	return int16(t)
}
func barrettReduce(a int16) int16 {
	var t int16
	const v int16 = ((1 << 26) + paramsQ/2) / paramsQ
	t = int16((int32(v)*int32(a) + (1 << 25)) >> 26)
	t *= paramsQ
	return a - t
}

// baseMul is multiplication of polynomial in Zq[X]/(X^2-zeta)
//and is used for multiplication of element in Rq in NTT domain
func baseMul(a, b []int16, zeta int16) []int16 {
	var res = make([]int16, 2)

	res[0] = fqmul(a[1], b[1])
	res[0] = fqmul(res[0], zeta)
	res[0] += fqmul(a[0], b[0])

	res[1] = fqmul(a[0], b[1])
	res[1] += fqmul(a[1], b[0])

	return res
}

func randomBytes(length int) []byte {
	res := make([]byte, length)
	for {
		if _, err := rand.Read(res); err == nil {
			return res
		}
	}
}

// rejectUniform runs rejection sampling on uniform random bytes to generate
//uniform random integers mod q
func rejectUniform(length int, buf []byte) []int16 {
	res := make([]int16, 0, length)
	var ctr, pos int
	var val0, val1 uint16
	for ctr < length && pos+3 <= len(buf) {
		val0 = (uint16(buf[pos+0]>>0) | (uint16(buf[pos+1]) << 8)) & 0xFFF
		val1 = (uint16(buf[pos+1]>>4) | (uint16(buf[pos+2]) << 4)) & 0xFFF
		pos += 3

		if val0 < paramsQ {
			res = append(res, int16(val0))
			ctr++
		}
		if ctr < length && val1 < paramsQ {
			res = append(res, int16(val1))
			ctr++
		}

	}
	return res
}

// generateMatrix deterministically generates matrix A (or the transpose of A)
//from a seed. Entries of the matrix are polynomials that look
//uniformly random. Performs rejection sampling on output of
//a XOF, the output is in NTT domain
func generateMatrix(pp *ParamSet, seed []byte, transposed bool) ([]*polyVec, error) {
	if len(seed) != paramsSymBytes {
		return nil, ErrInvalidLength
	}
	var err error
	res := make([]*polyVec, pp.paramsK)
	buf := make([]byte, 4*168)
	XOF := sha3.NewShake128()
	for i := 0; i < pp.paramsK; i++ {
		res[i] = newPolyVec(pp)
		for j := 0; j < pp.paramsK; j++ {
			XOF.Reset()
			if transposed {
				_, err = XOF.Write(append(seed, byte(i), byte(j)))

			} else {
				_, err = XOF.Write(append(seed, byte(j), byte(i)))
			}
			if err != nil {
				return nil, err
			}

			_, err = XOF.Read(buf)
			if err != nil {
				return nil, err
			}
			got := rejectUniform(paramsN, buf)
			for len(got) < paramsN {
				newBuf := make([]byte, 168)
				_, err = XOF.Read(newBuf)
				if err != nil {
					return nil, err
				}
				got = append(got, rejectUniform(paramsN-len(got), newBuf)...)
			}
			for k := 0; k < paramsN; k++ {
				res[i].vector[j].coeffs[k] = got[k]
			}
		}
	}
	return res, nil
}
