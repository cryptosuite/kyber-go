package kyber

func KeyPair(p *ParameterSet, seed []byte) ([]byte, []byte, error) {
	pk, sk, err := p.CryptoKemKeyPair(seed)
	if err != nil {
		return nil, nil, err
	}
	return pk.Bytes(), sk.Bytes(), nil
}

func Encaps(p *ParameterSet, serializedPK []byte) (cipherText []byte, sharedSecret []byte, err error) {
	pk, err := p.PublicKeyFromBytes(serializedPK)
	if err != nil {
		return nil, nil, err
	}
	return pk.CryptoKemEnc()

}

func Decaps(p *ParameterSet, serializedSK []byte, cipherText []byte) (sharedSecret []byte) {
	sk, err := p.SecretKeyFromBytes(serializedSK)
	if err != nil {
		return nil
	}
	return sk.CryptoKemDec(cipherText)
}
