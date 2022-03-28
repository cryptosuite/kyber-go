package kyber

const (
	kyberN = 256
	kyberQ = 7681

	//SymBytes is size in bytes of shared key, hashes, and seeds
	SymBytes = 32

	polyBytes           = 416
	polyCompressedBytes = 96
)

var (
	//Kyber512 with...
	Kyber512 = setParams("Kyber512", 2)
	//Kyber768 with...
	Kyber768 = setParams("Kyber768", 3)
	//Kyber1024 with...
	Kyber1024 = setParams("Kyber1024", 4)
)

//ParameterSet is what it is.
type ParameterSet struct {
	name   string
	kyberK int

	eta int

	polyVecBytes           int
	polyVecCompressedBytes int

	indcpaMsgBytes       int
	indcpaPublicKeyBytes int
	indcpaSecretKeyBytes int
	indcpaBytes          int

	publicKeyBytes  int
	secretKeyBytes  int
	ciphertextBytes int

	sharedSecretBytes int
}

//WhichParamenterSet returns Kyber512,Kyber768 or Kyber1024 in string fmt
func (p *ParameterSet) WhichParamenterSet() string {
	return p.name
}

//CryptoSecretKeyBytes returns the size of secretKeyBytes
func (p *ParameterSet) CryptoSecretKeyBytes() int {
	return p.secretKeyBytes
}

//CryptoPublicKeyBytes returns the size of publicKeyBytes
func (p *ParameterSet) CryptoPublicKeyBytes() int {
	return p.publicKeyBytes
}

//CryptoCiphertextBytes returns the size of ciphertextBytes
func (p *ParameterSet) CryptoCiphertextBytes() int {
	return p.ciphertextBytes
}

//CryptoSharedSecretBytes returns the size of ss
func (p *ParameterSet) CryptoSharedSecretBytes() int {
	return p.sharedSecretBytes
}

func setParams(name string, kyberK int) *ParameterSet {
	var p ParameterSet

	p.name = name
	p.kyberK = kyberK

	switch kyberK {
	case 2:
		p.eta = 5
	case 3:
		p.eta = 4
	case 4:
		p.eta = 3
	default:
		panic("kyberK: 2-Kyber512, 3-Kyber768, 4-Kyber1024")
	}

	p.polyVecBytes = kyberK * polyBytes
	p.polyVecCompressedBytes = kyberK * 352

	p.indcpaMsgBytes = SymBytes
	p.indcpaPublicKeyBytes = p.polyVecCompressedBytes + SymBytes
	p.indcpaSecretKeyBytes = p.polyVecBytes
	p.indcpaBytes = p.polyVecCompressedBytes + polyCompressedBytes

	p.publicKeyBytes = p.indcpaPublicKeyBytes
	p.secretKeyBytes = p.indcpaSecretKeyBytes + p.indcpaPublicKeyBytes + 2*SymBytes
	p.ciphertextBytes = p.indcpaBytes

	p.sharedSecretBytes = 32

	return &p

}
