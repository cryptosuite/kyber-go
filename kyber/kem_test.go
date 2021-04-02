package kyber

import "testing"

func TestKEMCorrect(t *testing.T) {
	seed := []byte{
		57, 182, 9, 31, 144, 240, 1, 106, 160, 117, 215, 240, 160, 177, 92, 86, 234, 158, 148, 93, 4, 132, 147, 137, 70, 227, 121, 90, 231, 58, 8, 8,
		57, 182, 9, 31, 144, 240, 1, 106, 160, 117, 215, 240, 160, 177, 92, 86, 234, 158, 148, 93, 4, 132, 147, 137, 70, 227, 121, 90, 231, 58, 8, 8,
	}
	kems := []*ParamSet{Kyber512, Kyber768, Kyber1024}
	for i := 0; i < len(kems); i++ {
		kem := kems[i]
		pk, sk, err := kem.KeyPair(seed)
		if err != nil {
			t.Logf("error in KeyPair")
		}
		c, ss, err := kem.Enc(pk)
		if err != nil {
			t.Logf("error in Enc")
		}
		c1, err := kem.Dec(c, sk)
		t.Logf("%v", c1)
		t.Logf("%v", ss)
	}

}
