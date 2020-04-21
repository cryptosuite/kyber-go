package kyber

const (
	K                      = 3
	PolyCompressedBytes    = 96
	PolyvecCompressedBytes = K * 352
	IndcpaBytes            = PolyvecCompressedBytes + PolyCompressedBytes
	CiphertextBytes        = IndcpaBytes

	Symbytes               = 32
	Polyveccompressedbytes = K * 352
	IndcpaPublickeybytes   = Polyveccompressedbytes + Symbytes
	Polybytes              = 416
	Polyvecbytes           = K * Polybytes
	IndcpaSecretkeybytes   = Polyvecbytes

	Publickeybytes  = IndcpaPublickeybytes
	Secretkeybytes  = IndcpaSecretkeybytes + IndcpaPublickeybytes + 2*Symbytes /* 32 bytes of additional space to save H(pk) */
	Ciphertextbytes = IndcpaBytes

	CryptoSecretkeybytes  = Secretkeybytes
	CryptoPublickeybytes  = Publickeybytes
	CryptoCiphertextbytes = Ciphertextbytes
	CryptoBytes           = Symbytes
)

func CryptoKemKeypair(seed []byte) (pk [CryptoPublickeybytes]byte, sk [CryptoSecretkeybytes]byte) {
	var pk2 [CryptoPublickeybytes]byte
	var sk2 [CryptoSecretkeybytes]byte

	//to do
	//if seed == nil, generate random pk and sk

	return pk2, sk2
}

func CryptoKemEnc(pk [CryptoPublickeybytes]byte) (ct [CryptoCiphertextbytes]byte, ss [CryptoBytes]byte) {
	var ct2 [CryptoCiphertextbytes]byte
	var ss2 [CryptoBytes]byte

	//to do

	return ct2, ss2
}

func CryptoKemDec(ct [CryptoCiphertextbytes]byte, sk [CryptoSecretkeybytes]byte) (ss [CryptoBytes]byte) {
	var ss2 [CryptoBytes]byte

	//to do

	return ss2
}
