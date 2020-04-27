package kyber

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"

	"golang.org/x/crypto/sha3"
)

var (
	// ErrInvalidKeySize is the error returned when a byte serailized key is an invalid size.
	ErrInvalidKeySize = errors.New("kyber: invalid key size")

	// ErrInvalidCipherTextSize is the error thrown via a panic when a byte serialized ciphertext is an invalid size.
	ErrInvalidCipherTextSize = errors.New("kyber: invalid ciphertext size")

	// ErrInvalidPrivateKey is the error returned when a byte serialized
	// private key is malformed.
	ErrInvalidPrivateKey = errors.New("kyber: invalid private key")
)

/*******precomp*********/

//PublicKey is related to ParameterSet
type PublicKey struct {
	pk *indcpaPublicKey
	p  *ParameterSet
}

//SecretKey includes Publickey
type SecretKey struct {
	PublicKey
	sk *indcpaSecretKey
	z  []byte
}

//Bytes returns PublicKey in form []byte
func (pk *PublicKey) Bytes() []byte {
	return pk.pk.toBytes()
}

//Bytes returns SecretKey in form []byte
func (sk *SecretKey) Bytes() []byte {
	p := sk.PublicKey.p

	b := make([]byte, 0, p.secretKeyBytes)
	b = append(b, sk.sk.packed...)
	b = append(b, sk.PublicKey.pk.packed...)
	b = append(b, sk.PublicKey.pk.h[:]...)
	b = append(b, sk.z...)

	return b
}

// PublicKeyFromBytes []byte to struct
func (p *ParameterSet) PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	pk := &PublicKey{
		pk: new(indcpaPublicKey),
		p:  p,
	}

	if err := pk.pk.fromBytes(p, b); err != nil {
		return nil, err
	}

	return pk, nil
}

// SecretKeyFromBytes []byte to struct
func (p *ParameterSet) SecretKeyFromBytes(b []byte) (*SecretKey, error) {
	if len(b) != p.secretKeyBytes {
		return nil, ErrInvalidKeySize
	}

	sk := new(SecretKey)
	sk.sk = new(indcpaSecretKey)
	sk.z = make([]byte, SymBytes)
	sk.PublicKey.pk = new(indcpaPublicKey)
	sk.PublicKey.p = p

	off := p.indcpaSecretKeyBytes
	if err := sk.PublicKey.pk.fromBytes(p, b[off:off+p.publicKeyBytes]); err != nil {
		return nil, err
	}
	off += p.publicKeyBytes
	if !bytes.Equal(sk.PublicKey.pk.h[:], b[off:off+SymBytes]) {
		return nil, ErrInvalidPrivateKey
	}
	off += SymBytes
	copy(sk.z, b[off:])

	if err := sk.sk.fromBytes(p, b[:p.indcpaSecretKeyBytes]); err != nil {
		return nil, err
	}

	return sk, nil
}

/*******METHODS*********/

//CryptoKemKeyPair is a method of Params Set
func (p *ParameterSet) CryptoKemKeyPair(seed []byte) (*PublicKey, *SecretKey, error) {
	kp := new(SecretKey)
	var indcpaSeed []byte

	if seed != nil {
		SeedBuf := sha3.Sum512(seed[:])
		indcpaSeed = make([]byte, SymBytes)
		copy(indcpaSeed[:], SeedBuf[:SymBytes])
		kp.z = make([]byte, SymBytes)
		copy(kp.z[:], SeedBuf[SymBytes:])
	}

	var err error
	if kp.PublicKey.pk, kp.sk, err = p.indcpaKeyPair(indcpaSeed); err != nil {
		return nil, nil, err
	}

	kp.PublicKey.p = p

	if kp.z == nil {
		kp.z = make([]byte, SymBytes)
		if _, err := io.ReadFull(rand.Reader, kp.z); err != nil {
			return nil, nil, err
		}
	}

	return &kp.PublicKey, kp, nil
}

//CryptoKemEnc is a method of pk
func (pk *PublicKey) CryptoKemEnc() (cipherText []byte, sharedSecret []byte, err error) {
	var buf [SymBytes]byte
	if _, err = io.ReadFull(rand.Reader, buf[:]); err != nil {
		return nil, nil, err
	}
	buf = sha3.Sum256(buf[:])

	hKr := sha3.New512()
	hKr.Write(buf[:])
	hKr.Write(pk.pk.h[:])
	kr := hKr.Sum(nil)

	cipherText = make([]byte, pk.p.ciphertextBytes)
	pk.p.indcpaEncrypt(cipherText, buf[:], pk.pk, kr[SymBytes:])

	hc := sha3.Sum256(cipherText)
	copy(kr[SymBytes:], hc[:])
	hSs := sha3.New256()
	hSs.Write(kr)
	sharedSecret = hSs.Sum(nil)

	return
}

//CryptoKemDec is a method of sk
func (sk *SecretKey) CryptoKemDec(cipherText []byte) (sharedSecret []byte) {
	var buf [2 * SymBytes]byte

	p := sk.PublicKey.p
	if len(cipherText) != p.CryptoCiphertextBytes() {
		panic(ErrInvalidCipherTextSize)
	}
	p.indcpaDecrypt(buf[:SymBytes], cipherText, sk.sk)

	copy(buf[SymBytes:], sk.PublicKey.pk.h[:])
	kr := sha3.Sum512(buf[:])

	cmp := make([]byte, p.ciphertextBytes)
	p.indcpaEncrypt(cmp, buf[:SymBytes], sk.PublicKey.pk, kr[SymBytes:])

	hc := sha3.Sum256(cipherText)
	copy(kr[SymBytes:], hc[:])

	fail := subtle.ConstantTimeSelect(subtle.ConstantTimeCompare(cipherText, cmp), 0, 1)
	subtle.ConstantTimeCopy(fail, kr[SymBytes:], sk.z)

	h := sha3.New256()
	h.Write(kr[:])
	sharedSecret = h.Sum(nil)

	return
}
