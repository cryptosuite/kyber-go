package kyber

const (
	paramsN = 256
	paramsQ = 3329

	paramsSymBytes = 32 //size in bytes of hashes and seeds
	paramsSSBytes  = 32 //size in bytes of shared key

	paramsPolyBytes = 384

	paramsINDCPAMsgBytes = paramsSymBytes
)

type ParamSet struct {
	name string

	paramsK    int
	paramsETA1 int
	paramsETA2 int
	//paramsU    int
	//paramsV    int

	//paramsPolyBytes          int
	paramsPolyCompressedBytes       int
	paramsPolyVectorBytes           int // paramsK * paramsPolyBytes
	paramsPolyVectorCompressedBytes int //paramsK * [320/352]

	paramsINDCPAPublicKeyBytes int // paramsPolyVectorBytes + paramsSymBytes
	paramsINDCPASecretKeyBytes int // paramsPolyVectorBytes
	paramsINDCPABytes          int // paramsPolyVectorCompressedBytes + paramsPolyCompressedBytes

	paramsPublicKeyBytes  int // paramsINDCPAPublicKeyBytes
	paramsSecretKeyBytes  int // paramsINDCPASecretKeyBytes + paramsINDCPAPublicKeyBytes + 2*paramsSymBytes // 32 bytes of additional space to save H(t)
	paramsCiphertextBytes int // paramsINDCPABytes
}

func (pp *ParamSet) ParamsCiphertextBytes() int {
	return pp.paramsCiphertextBytes
}

func (pp *ParamSet) ParamsSecretKeyBytes() int {
	return pp.paramsSecretKeyBytes
}

func (pp *ParamSet) ParamsPublicKeyBytes() int {
	return pp.paramsPublicKeyBytes
}

func newParamSet(name string, paramsK int, paramsETA1 int, paramsETA2 int, paramsU int, paramsV int) *ParamSet {
	res := new(ParamSet)
	res.name = name
	res.paramsK = paramsK
	res.paramsETA1 = paramsETA1
	res.paramsETA2 = paramsETA2
	//res.paramsU = paramsU
	//res.paramsV = paramsV
	switch res.paramsK {
	case 2:
		res.paramsPolyCompressedBytes = 128
		res.paramsPolyVectorCompressedBytes = res.paramsK * 320
	case 3:
		res.paramsPolyCompressedBytes = 128
		res.paramsPolyVectorCompressedBytes = res.paramsK * 320
	case 4:
		res.paramsPolyCompressedBytes = 160
		res.paramsPolyVectorCompressedBytes = res.paramsK * 352
	}
	res.paramsPolyVectorBytes = res.paramsK * paramsPolyBytes

	res.paramsINDCPAPublicKeyBytes = res.paramsPolyVectorBytes + paramsSymBytes
	res.paramsINDCPASecretKeyBytes = res.paramsPolyVectorBytes
	res.paramsINDCPABytes = res.paramsPolyVectorCompressedBytes + res.paramsPolyCompressedBytes

	res.paramsPublicKeyBytes = res.paramsINDCPAPublicKeyBytes
	res.paramsSecretKeyBytes = res.paramsINDCPASecretKeyBytes + res.paramsINDCPAPublicKeyBytes + 2*paramsSymBytes // 32 bytes of additional space to save H(t)
	res.paramsCiphertextBytes = res.paramsINDCPABytes

	return res
}

func (pp *ParamSet) KeyPair(seed []byte) ([]byte, []byte, error) {
	return KeyPair(pp, seed)
}
func (pp *ParamSet) Enc(pk []byte) ([]byte, []byte, error) {
	return Enc(pp, pk)
}
func (pp *ParamSet) Dec(cipher []byte, sk []byte) ([]byte, error) {
	return Dec(pp, cipher, sk)
}

var Kyber512 = newParamSet("Kyber512", 2, 3, 2, 10, 4)
var Kyber768 = newParamSet("Kyber768", 3, 2, 2, 10, 4)
var Kyber1024 = newParamSet("Kyber1024", 4, 2, 2, 11, 5)
