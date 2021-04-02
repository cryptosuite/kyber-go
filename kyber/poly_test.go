package kyber

import (
	"bytes"
	"testing"
)

func Test_poly_FromMsg(t *testing.T) {
	msg := randomBytes(paramsSymBytes)
	p := new(poly)
	err := p.fromMsg(msg)
	if err != nil {
		t.Log("error in fromMsg")
	}
	got := p.toMsg()
	if !bytes.Equal(got, msg) {
		t.Log("mismatch between fromMsg and toMsg")
	}
}

func Test_poly_FromBytes(t *testing.T) {
	seed := randomBytes(paramsSymBytes)
	A, err := generateMatrix(Kyber512, seed, false)
	if err != nil {
		t.Log("error in generate matrix")
	}
	byteA0 := A[0].toBytes(Kyber512)
	p := new(poly)
	err = p.fromBytes(byteA0[:paramsPolyBytes])
	if err != nil {
		t.Log("error in fromBytes")
	}
	if !bytes.Equal(p.toBytes(), byteA0[:paramsPolyBytes]) {
		t.Log("mismatch between fromBytes and toBytes")
	}
}

//func Test_poly_Compress(t *testing.T) {
//	seed := randomBytes(paramsSymBytes)
//	kem:=Kyber512
//	A, err := generateMatrix(kem, seed, false)
//	if err != nil {
//		t.Log("error in generate matrix")
//	}
//
//	byteA0 := A[0].vector[0].compress(kem)
//	p := new(poly)
//	err = p.decompress(kem,byteA0)
//	if err != nil {
//		t.Log("error in fromBytes")
//	}
//	for i := 0; i < len(p.coeffs); i++ {
//		if (A[0].vector[0].coeffs[i]-p.coeffs[i] > (paramsQ >> 14)) || (A[0].vector[0].coeffs[i]-p.coeffs[i] < -(paramsQ >> 14)) {
//			t.Log("mismatch between compress and decompress")
//		}
//	}
//}
