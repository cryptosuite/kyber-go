package kyber

func ntt(p *[kyberN]uint16) {
	var j, k int
	var zeta, t uint16

	k = 1
	for level := 7; level >= 0; level-- {
		for start := 0; start < kyberN; start = j + (1 << uint(level)) {
			zeta = zetas[k]
			k++
			for j = start; j < start+(1<<uint(level)); j++ {
				t = montgomeryReduce(uint32(zeta) * uint32(p[j+(1<<uint(level))]))
				p[j+(1<<uint(level))] = barrettReduce(p[j] + 4*kyberQ - t)

				if level&1 == 1 {
					p[j] = p[j] + t
				} else {
					p[j] = barrettReduce(p[j] + t)
				}
			}
		}
	}
}

func invntt(a *[kyberN]uint16) {
	var jTwiddle int
	var temp, W uint16
	var t uint32

	for level := 0; level < 8; level++ {
		for start := 0; start < (1 << uint(level)); start++ {
			jTwiddle = 0
			for j := start; j < kyberN-1; j += 2 * (1 << uint(level)) {
				W = omegasInvBitrevMontgomery[jTwiddle]
				jTwiddle++

				temp = a[j]

				if level&1 == 1 {
					a[j] = barrettReduce(temp + a[j+(1<<uint(level))])
				} else {
					a[j] = temp + a[j+(1<<uint(level))]
				}

				t = uint32(W) * (uint32(temp) + 4*kyberQ - uint32(a[j+(1<<uint(level))]))

				a[j+(1<<uint(level))] = montgomeryReduce(t)
			}
		}
	}

	for i, v := range psisInvMontgomery {
		a[i] = montgomeryReduce(uint32(a[i]) * uint32(v))
	}
}
