package kyber

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/sha3"
)

/*******precomp*********/

type indcpaPublicKey struct {
	packed []byte
	h      [32]byte
}

type indcpaSecretKey struct {
	packed []byte
}

//to and from bytes for indcpaPK
func (pk *indcpaPublicKey) toBytes() []byte {
	return pk.packed
}

func (pk *indcpaPublicKey) fromBytes(p *ParameterSet, b []byte) error {
	if len(b) != p.indcpaPublicKeyBytes {
		return ErrInvalidKeySize
	}

	pk.packed = make([]byte, len(b))
	copy(pk.packed, b)
	pk.h = sha3.Sum256(b)

	return nil
}

//to and from bytes for indcpaSK
func (sk *indcpaSecretKey) fromBytes(p *ParameterSet, b []byte) error {
	if len(b) != p.indcpaSecretKeyBytes {
		return ErrInvalidKeySize
	}

	sk.packed = make([]byte, len(b))
	copy(sk.packed, b)

	return nil
}

//a method for polyvec
func (v *polyVec) compressedSize() int {
	return len(v.vec) * 352
}

/*********************/

//pack and unpack for PK
func packPK(r []byte, pk *polyVec, seed []byte) {
	pk.compress(r)
	copy(r[pk.compressedSize():], seed[:SymBytes])
}

func unpackPK(pk *polyVec, seed, packedPk []byte) {
	pk.decompress(packedPk)

	idx := pk.compressedSize()
	copy(seed, packedPk[idx:idx+SymBytes])
}

//pack and unpack for Ciphertext
func packCiphertext(r []byte, b *polyVec, v *poly) {
	b.compress(r)
	v.compress(r[b.compressedSize():])
}

func unpackCiphertext(b *polyVec, v *poly, c []byte) {
	b.decompress(c)
	v.decompress(c[b.compressedSize():])
}

//pack and unpack for SK
func packSK(r []byte, sk *polyVec) {
	sk.toBytes(r)
}

func unpackSK(sk *polyVec, packedSk []byte) {
	sk.fromBytes(packedSk)
}

//gen matrix, transposed deciding whether 0-A or 1-A^T is generated
func genMatrix(a []polyVec, seed []byte, transposed bool) {
	const (
		shake128Rate = 168
		maxnBlocks   = 4
	)
	var val uint16
	var buf [shake128Rate * maxnBlocks]byte
	var extSeed [SymBytes + 2]byte

	copy(extSeed[:SymBytes], seed)

	xof := sha3.NewShake128()

	for i, v := range a {
		for j, p := range v.vec {
			if transposed {
				extSeed[SymBytes] = byte(i)
				extSeed[SymBytes+1] = byte(j)
			} else {
				extSeed[SymBytes] = byte(j)
				extSeed[SymBytes+1] = byte(i)
			}

			xof.Write(extSeed[:])
			xof.Read(buf[:])

			for ctr, pos, maxPos := 0, 0, len(buf); ctr < kyberN; {
				val = (uint16(buf[pos]) | (uint16(buf[pos+1]) << 8)) & 0x1fff
				if val < kyberQ {
					p.coeffs[ctr] = val
					ctr++
				}
				if pos += 2; pos == maxPos {
					xof.Read(buf[:shake128Rate])
					pos, maxPos = 0, shake128Rate
				}
			}

			xof.Reset()
		}
	}
}

/*********************/

func (p *ParameterSet) allocMatrix() []polyVec {
	m := make([]polyVec, 0, p.kyberK)
	for i := 0; i < p.kyberK; i++ {
		m = append(m, p.allocPolyVec())
	}
	return m
}

func (p *ParameterSet) allocPolyVec() polyVec {
	vec := make([]*poly, 0, p.kyberK)
	for i := 0; i < p.kyberK; i++ {
		vec = append(vec, new(poly))
	}

	return polyVec{vec}
}

/*******METHODS*********/

//key pair
func (p *ParameterSet) indcpaKeyPair(indcpaSeed []byte) (*indcpaPublicKey, *indcpaSecretKey, error) {
	sk := &indcpaSecretKey{
		packed: make([]byte, p.indcpaSecretKeyBytes),
	}
	pk := &indcpaPublicKey{
		packed: make([]byte, p.indcpaPublicKeyBytes),
	}

	var indcpaSeedBuf [64]byte
	var publicSeed, noiseSeed []byte
	publicSeed = make([]byte, SymBytes)
	noiseSeed = make([]byte, SymBytes)

	if indcpaSeed != nil {
		indcpaSeedBuf = sha3.Sum512(indcpaSeed[:])
	} else {
		buf := make([]byte, SymBytes)
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			return nil, nil, err
		}
		indcpaSeedBuf = sha3.Sum512(buf[:])
	}

	copy(publicSeed[:], indcpaSeedBuf[:SymBytes])
	copy(noiseSeed[:], indcpaSeedBuf[SymBytes:])

	a := p.allocMatrix()
	genMatrix(a, publicSeed, false)

	var nonce byte
	skpv := p.allocPolyVec()
	for _, pv := range skpv.vec {
		pv.getNoise(noiseSeed, nonce, p.eta)
		nonce++
	}

	skpv.ntt()

	e := p.allocPolyVec()
	for _, pv := range e.vec {
		pv.getNoise(noiseSeed, nonce, p.eta)
		nonce++
	}

	// matrix-vector multiplication
	pkpv := p.allocPolyVec()
	for i, pv := range pkpv.vec {
		pv.pointwiseAcc(&skpv, &a[i])
	}

	pkpv.invntt()
	pkpv.add(&pkpv, &e)

	packSK(sk.packed, &skpv)
	packPK(pk.packed, &pkpv, publicSeed)
	pk.h = sha3.Sum256(pk.packed)

	return pk, sk, nil
}

//enc
func (p *ParameterSet) indcpaEncrypt(c, m []byte, pk *indcpaPublicKey, coins []byte) {
	var k, v, epp poly
	var seed [SymBytes]byte

	pkpv := p.allocPolyVec()
	unpackPK(&pkpv, seed[:], pk.packed)

	k.fromMsg(m)

	pkpv.ntt()

	at := p.allocMatrix()
	genMatrix(at, seed[:], true)

	var nonce byte
	sp := p.allocPolyVec()
	for _, pv := range sp.vec {
		pv.getNoise(coins, nonce, p.eta)
		nonce++
	}

	sp.ntt()

	ep := p.allocPolyVec()
	for _, pv := range ep.vec {
		pv.getNoise(coins, nonce, p.eta)
		nonce++
	}

	// matrix-vector multiplication
	bp := p.allocPolyVec()
	for i, pv := range bp.vec {
		pv.pointwiseAcc(&sp, &at[i])
	}

	bp.invntt()
	bp.add(&bp, &ep)

	v.pointwiseAcc(&pkpv, &sp)
	v.invntt()

	epp.getNoise(coins, nonce, p.eta)

	v.add(&v, &epp)
	v.add(&v, &k)

	packCiphertext(c, &bp, &v)
}

//dec
func (p *ParameterSet) indcpaDecrypt(m, c []byte, sk *indcpaSecretKey) {
	var v, mp poly

	skpv, bp := p.allocPolyVec(), p.allocPolyVec()
	unpackCiphertext(&bp, &v, c)
	unpackSK(&skpv, sk.packed)

	bp.ntt()

	mp.pointwiseAcc(&skpv, &bp)
	mp.invntt()

	mp.sub(&mp, &v)

	mp.toMsg(m)
}
