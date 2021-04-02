package kyber

import (
	"bytes"
	"testing"
)

func Test_polyVec_ToBytes(t *testing.T) {
	seed := []byte{57, 182, 9, 31, 144, 240, 1, 106, 160, 117, 215, 240, 160, 177, 92, 86, 234, 158, 148, 93, 4, 132, 147, 137, 70, 227, 121, 90, 231, 58, 8, 8}
	kem := Kyber768
	A, err := generateMatrix(kem, seed, false)
	if err != nil {
		t.Logf("error")
	}
	A0B := A[0].toBytes(kem)
	p := newPolyVec(kem)
	err = p.fromBytes(kem, A0B)
	if err != nil {
		t.Logf("error2")
	}
	got := p.toBytes(kem)
	if !bytes.Equal(got, A0B) {
		t.Logf("error3")
	}
}
