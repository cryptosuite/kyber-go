package kyber

import (
	"bytes"
	"testing"
)

func TestINDCPACorrect(t *testing.T) {
	kems := []*ParamSet{Kyber512, Kyber768, Kyber1024}

	seed := []byte{57, 182, 9, 31, 144, 240, 1, 106, 160, 117, 215, 240, 160, 177, 92, 86, 234, 158, 148, 93, 4, 132, 147, 137, 70, 227, 121, 90, 231, 58, 8, 8}
	for i := 0; i < len(kems); i++ {
		kem := kems[i]
		seed, pk, sk, err := INDCPAKeyPair(kem, seed)
		if err != nil {
			t.Log("error in INDCPAKeyPair")
		}
		seed1, pk1, sk1, err := INDCPAKeyPair(kem, seed)
		if err != nil || !bytes.Equal(seed, seed1) || !bytes.Equal(pk, pk1) || !bytes.Equal(sk, sk1) {
			t.Log("error in twice INDCPAKeyPair")
		}

		msg := []byte{57, 182, 9, 31, 144, 240, 1, 106, 160, 117, 215, 240, 160, 177, 92, 86, 234, 158, 148, 93, 4, 132, 147, 137, 70, 227, 121, 90, 231, 58, 8, 8}
		coin := []byte{57, 182, 9, 31, 144, 240, 1, 106, 160, 117, 215, 240, 160, 177, 92, 86, 234, 158, 148, 93, 4, 132, 147, 137, 70, 227, 121, 90, 231, 58, 8, 8}
		c, err := INDCPAEnc(kem, msg, pk, coin)
		if err != nil {
			t.Log("error in INDCPAENC")
		}
		c1, _ := INDCPAEnc(kem, msg, pk, coin)
		if !bytes.Equal(c, c1) {
			t.Log("error in twice INDCPAENC")
		}

		gotMsg, err := INDCPADec(kem, c, sk)
		if err != nil || !bytes.Equal(msg, gotMsg) {
			t.Log("error in INDCPADec")
		}
	}
}
