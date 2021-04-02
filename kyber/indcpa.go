package kyber

import (
	"golang.org/x/crypto/sha3"
)

type INDCPAPublicKey struct {
	t    polyVec
	seed [paramsSymBytes]byte
}

func NewINDCPAPublicKey(pp *ParamSet) *INDCPAPublicKey {
	return &INDCPAPublicKey{t: *newPolyVec(pp)}
}

// Unpack de-serializes public key from a byte array;
//approximate inverse of Pack
func (pk *INDCPAPublicKey) Unpack(pp *ParamSet, a []byte) error {
	if len(a) != pp.paramsINDCPAPublicKeyBytes {
		return ErrInvalidLength
	}
	err := pk.t.fromBytes(pp, a[:pp.paramsPolyVectorBytes])
	if err != nil {
		return err
	}
	copy(pk.seed[:], a[pp.paramsPolyVectorBytes:])
	return nil
}

// Pack serializes the public key as concatenation of the serialized
//vector of polynomials t and the public seed used to generate the matrix A.
func (pk *INDCPAPublicKey) Pack(pp *ParamSet) []byte {
	res := make([]byte, pp.paramsINDCPAPublicKeyBytes)
	copy(res[:pp.paramsPolyVectorBytes], pk.t.toBytes(pp))
	copy(res[pp.paramsPolyVectorBytes:], pk.seed[:])
	return res
}

type INDCPASecretKey struct {
	s polyVec
}

func NewINDCPASecretKey(pp *ParamSet) *INDCPASecretKey {
	return &INDCPASecretKey{s: *newPolyVec(pp)}
}

// Pack serializes the secret key
func (sk *INDCPASecretKey) Pack(pp *ParamSet) []byte {
	return sk.s.toBytes(pp)
}

// Unpack de-serialize the secret key; inverse of Serialize
func (sk *INDCPASecretKey) Unpack(pp *ParamSet, a []byte) error {
	return sk.s.fromBytes(pp, a)
}

type INDCPACiphertext struct {
	u polyVec
	v poly
}

func NewINDCPACiphertext(pp *ParamSet) *INDCPACiphertext {
	return &INDCPACiphertext{
		u: *newPolyVec(pp),
		v: poly{},
	}
}

// Pack serializes the ciphertext as concatenation of the compressed and serialized
//vector of polynomials u and the compressed and serialized polynomial v
func (cp *INDCPACiphertext) Pack(pp *ParamSet) []byte {
	res := make([]byte, 0, pp.paramsINDCPABytes)
	res = append(res, cp.u.compress(pp)[:]...)
	res = append(res, cp.v.compress(pp)[:]...)
	return res
}

// Unpack De-serialize and decompress ciphertext from a byte array;
//approximate inverse of Pack
func (cp *INDCPACiphertext) Unpack(pp *ParamSet, a []byte) error {
	if len(a) != pp.paramsINDCPABytes {
		return ErrInvalidLength
	}
	err := cp.u.decompress(pp, a[:pp.paramsPolyVectorCompressedBytes])
	if err != nil {
		return err
	}
	err = cp.v.decompress(pp, a[pp.paramsPolyVectorCompressedBytes:])
	if err != nil {
		return err
	}
	return nil
}

// INDCPAKeyPair generates public and private key for the CPA-secure
//public-key encryption scheme underlying Kyber
func INDCPAKeyPair(pp *ParamSet, seed []byte) ([]byte, []byte, []byte, error) {
	var err error
	sk := NewINDCPASecretKey(pp)
	pk := NewINDCPAPublicKey(pp)
	e := newPolyVec(pp)
	var buf [64]byte
	if seed != nil {
		buf = sha3.Sum512(seed[:paramsSymBytes])
	} else {
		seed = randomBytes(paramsSymBytes)
		buf = sha3.Sum512(seed) //seed for t and s
	}
	A, err := generateMatrix(pp, buf[:paramsSymBytes], false)
	if err != nil {
		return seed, nil, nil, err
	}
	var nonce byte
	for i := 0; i < pp.paramsK; i++ {
		err = sk.s.vector[i].getNoiseETA1(pp, buf[paramsSymBytes:], nonce)
		nonce++
		if err != nil {
			return seed, nil, nil, err
		}
	}
	for i := 0; i < pp.paramsK; i++ {
		err = e.vector[i].getNoiseETA1(pp, buf[paramsSymBytes:], nonce)
		nonce++
		if err != nil {
			return seed, nil, nil, err
		}
	}
	sk.s.ntt(pp)
	e.ntt(pp)

	// t =A*s + e
	for i := 0; i < pp.paramsK; i++ {
		pk.t.vector[i] = *baseMulACCMontgomery(pp, A[i], &sk.s)
		pk.t.vector[i].toMont()
	}
	pk.t = *pk.t.add(pp, e)
	pk.t.reduce(pp)
	copy(pk.seed[:], buf[:paramsSymBytes]) // cache the public seed
	//skB:=sk.Pack(pp)
	//p:=newPolyVec(pp)
	//_ = p.fromBytes(pp,skB)
	//p.reduce(pp)
	//got := p.toBytes(pp)
	//if !bytes.Equal(skB,got){
	//}
	return seed, pk.Pack(pp), sk.Pack(pp), nil
}

// INDCPAEnc is encryption function of the CPA-secure
//public-key encryption scheme underlying Kyber.
func INDCPAEnc(pp *ParamSet, mB []byte, pkB []byte, coins []byte) ([]byte, error) {
	res := NewINDCPACiphertext(pp)

	// acquired message
	m := new(poly)
	err := m.fromMsg(mB)
	if err != nil {
		return nil, err
	}
	var nonce uint8

	pk := NewINDCPAPublicKey(pp)
	err = pk.Unpack(pp, pkB)
	if err != nil {
		return nil, err
	}

	// generate transposed matrix
	At, err := generateMatrix(pp, pk.seed[:], true)
	if err != nil {
		return nil, err
	}

	r := newPolyVec(pp)
	for i := 0; i < pp.paramsK; i++ {
		err = r.vector[i].getNoiseETA1(pp, coins, nonce)
		if err != nil {
			return nil, err
		}
		nonce++
	}

	e1 := newPolyVec(pp)
	for i := 0; i < pp.paramsK; i++ {
		err = e1.vector[i].getNoiseETA2(pp, coins, nonce)
		if err != nil {
			return nil, err
		}
		nonce++
	}

	e2 := new(poly)
	err = e2.getNoiseETA2(pp, coins, nonce)
	if err != nil {
		return nil, err
	}
	nonce++

	r.ntt(pp)

	// u=Ar+e1
	for i := 0; i < pp.paramsK; i++ {
		res.u.vector[i] = *baseMulACCMontgomery(pp, At[i], r)
	}
	res.u.invntt(pp)
	res.u = *res.u.add(pp, e1)
	res.u.reduce(pp)

	// v=t*r+e2+m
	res.v = *baseMulACCMontgomery(pp, &pk.t, r)
	res.v.invntt()
	res.v = *res.v.add(e2).add(m)
	res.v.reduce()

	return res.Pack(pp), nil
}

// INDCPADec is decryption function of the CPA-secure
//public-key encryption scheme underlying Kyber.
func INDCPADec(pp *ParamSet, cB []byte, skB []byte) ([]byte, error) {
	var err error

	c := NewINDCPACiphertext(pp)
	err = c.Unpack(pp, cB)
	if err != nil {
		return nil, err
	}

	// ntt(sk) but not ntt(s)_T?
	sk := NewINDCPASecretKey(pp)
	err = sk.Unpack(pp, skB)
	if err != nil {
		return nil, err
	}

	// m'=v-ntt_-1(ntt(s)_T*ntt(u))
	c.u.ntt(pp)
	got := baseMulACCMontgomery(pp, &sk.s, &c.u)
	got.invntt()

	got = c.v.sub(got)
	got.reduce()

	return got.toMsg(), nil
}
