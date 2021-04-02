package kyber

import (
	"bytes"
	"testing"
)

func Test_generateMatrix(t *testing.T) {
	seed := []byte{57, 182, 9, 31, 144, 240, 1, 106, 160, 117, 215, 240, 160, 177, 92, 86, 234, 158, 148, 93, 4, 132, 147, 137, 70, 227, 121, 90, 231, 58, 8, 8}
	A, err := generateMatrix(Kyber768, seed, false)
	if err != nil {
		t.Log(err)
	}
	for i := 0; i < len(A); i++ {
		for j := 0; j < len(A[0].vector); j++ {
			t.Logf("i=%d,j=%d,%v\n", i, j, A[i].vector[j])
		}
		t.Logf("\n")
	}
	At, err := generateMatrix(Kyber768, seed, true)
	if err != nil {
		t.Log(err)
	}
	for i := 0; i < len(At); i++ {
		for j := 0; j < len(At[0].vector); j++ {
			t.Logf("i=%d,j=%d,%v\n", i, j, At[i].vector[j])
		}
		t.Logf("\n")
	}
	for i := 0; i < len(A); i++ {
		for j := 0; j < len(A[0].vector); j++ {
			if !bytes.Equal(A[i].vector[j].toBytes(), At[j].vector[i].toBytes()) {
				t.Logf("error")
			}

		}

	}
}
