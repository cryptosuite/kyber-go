package kyber

const (
	qinv = 7679
	rlog = 18
)

func montgomeryReduce(a uint32) uint16 {
	var u uint32

	u = a * qinv
	u &= (1 << rlog) - 1
	u *= kyberQ
	a += u
	return uint16(a >> rlog)
}

func barrettReduce(a uint16) uint16 {
	var u uint32

	u = uint32(a >> 13)
	u *= kyberQ
	a -= uint16(u)
	return a
}

func freeze(x uint16) uint16 {
	var m, r uint16
	var c int16
	r = barrettReduce(x)

	m = r - kyberQ
	c = int16(m)
	c >>= 15
	r = m ^ ((r ^ m) & uint16(c))

	return r
}
