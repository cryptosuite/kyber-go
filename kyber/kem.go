package kyber

import (
	"crypto/subtle"
	"errors"
	"golang.org/x/crypto/sha3"
)

// KeyPair generates public and private key for CCA-secure Kyber key encapsulation mechanism
func KeyPair(pp *ParamSet, seed []byte) ([]byte, []byte, error) {
	if pp == nil {
		return nil, nil, errors.New("the param set is nil")
	}
	if seed == nil {
		return nil, nil, errors.New("the seed is nil")
	}
	if len(seed) != 2*paramsSymBytes {
		return nil, nil, ErrInvalidLength
	}
	pk := make([]byte, 0, pp.paramsPublicKeyBytes)
	sk := make([]byte, 0, pp.paramsSecretKeyBytes)
	tmp, INDPkB, INDSkB, err := INDCPAKeyPair(pp, seed[:paramsSymBytes])
	copy(seed[:paramsSymBytes], tmp[:])
	if err != nil {
		return nil, nil, err
	}
	pk = append(pk, INDPkB...)

	sk = append(sk, INDSkB...)
	sk = append(sk, INDPkB...)

	hash := make([]byte, paramsSymBytes)
	sha3.ShakeSum256(hash, INDPkB[:pp.paramsPublicKeyBytes-paramsSymBytes]) // compute H(t)
	sk = append(sk, hash...)
	sk = append(sk, seed[paramsSymBytes:]...) //random z for failure of kem
	return pk, sk, nil
}

// Enc generates cipher text and shared secret for given public key
func Enc(pp *ParamSet, pkB []byte) ([]byte, []byte, error) {
	if len(pkB) != pp.paramsPublicKeyBytes {
		return nil, nil, ErrInvalidLength
	}
	buf := make([]byte, 0, 2*paramsSymBytes)
	kr := make([]byte, 0, 2*paramsSymBytes)

	hash := make([]byte, paramsSymBytes)

	sha3.ShakeSum256(hash, randomBytes(paramsSymBytes))
	buf = append(buf, hash...)

	sha3.ShakeSum256(hash, pkB)
	buf = append(buf, hash...)

	h := sha3.Sum512(buf)
	kr = append(kr, h[:]...)
	ct, err := INDCPAEnc(pp, buf[:paramsSymBytes], pkB, kr[paramsSymBytes:])
	if err != nil {
		return nil, nil, err
	}

	sha3.ShakeSum256(hash, ct)
	copy(kr[paramsSymBytes:], hash[:])

	sha3.ShakeSum256(hash, kr)
	ss := make([]byte, paramsSSBytes)
	copy(ss, hash)
	return ct, ss, nil
}

// Dec generates shared secret for given cipher text and private key
func Dec(pp *ParamSet, cB []byte, skB []byte) ([]byte, error) {
	ss := make([]byte, paramsSSBytes)

	pk := skB[pp.paramsINDCPASecretKeyBytes : pp.paramsINDCPASecretKeyBytes+pp.paramsINDCPAPublicKeyBytes]
	sk := skB[:pp.paramsINDCPASecretKeyBytes]

	buf, err := INDCPADec(pp, cB[:], sk)
	kr := sha3.Sum512(append(buf, skB[pp.paramsSecretKeyBytes-2*paramsSymBytes:pp.paramsSecretKeyBytes-paramsSymBytes]...))
	cmp, err := INDCPAEnc(pp, buf, pk, kr[paramsSymBytes:])
	f := uint8(1 - subtle.ConstantTimeCompare(cB[:], cmp))
	krh := sha3.Sum256(cB[:])
	for i := 0; i < paramsSymBytes; i++ {
		b := skB[:pp.paramsSecretKeyBytes-paramsSymBytes+i]
		kr[i] = kr[i] ^ (f & (kr[i] ^ b[i]))
	}
	hash := make([]byte, paramsSymBytes)
	sha3.ShakeSum256(hash, append(kr[:paramsSymBytes], krh[:]...))
	copy(ss[:], hash[:])
	return ss, err
}
