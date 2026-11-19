package wallet

import (
	"encoding/binary"
	"math"
)

// withdrawalFrame bounds allocations before wire's decoder sees any count.
func withdrawalFrame(raw []byte, signed bool) bool {
	limit := 1024
	if signed {
		limit = 4096
	}
	if len(raw) > limit {
		return false
	}
	c := withdrawalCursor{raw: raw}
	v, ok := c.take(4)
	if !ok || binary.LittleEndian.Uint32(v) != 1 {
		return false
	}
	if signed {
		m, ok := c.take(2)
		if !ok || m[0] != 0 || m[1] != 1 {
			return false
		}
	}
	n, ok := c.compact()
	if !ok || n < 1 || n > 16 {
		return false
	}
	for i := uint64(0); i < n; i++ {
		if _, ok := c.take(36); !ok {
			return false
		}
		z, ok := c.compact()
		if !ok || z != 0 {
			return false
		}
		seq, ok := c.take(4)
		if !ok || binary.LittleEndian.Uint32(seq) != math.MaxUint32 {
			return false
		}
	}
	outs, ok := c.compact()
	if !ok || outs < 1 || outs > 2 {
		return false
	}
	for i := uint64(0); i < outs; i++ {
		if _, ok := c.take(8); !ok {
			return false
		}
		z, ok := c.compact()
		if !ok || z > 34 {
			return false
		}
		if _, ok := c.take(int(z)); !ok {
			return false
		}
	}
	if signed {
		for i := uint64(0); i < n; i++ {
			z, ok := c.compact()
			if !ok || z != 2 {
				return false
			}
			z, ok = c.compact()
			if !ok || z < 9 || z > 73 {
				return false
			}
			sig, ok := c.take(int(z))
			if !ok || sig[len(sig)-1] != 1 {
				return false
			}
			z, ok = c.compact()
			if !ok || z != 33 {
				return false
			}
			pub, ok := c.take(33)
			if !ok || (pub[0] != 2 && pub[0] != 3) {
				return false
			}
		}
	}
	lock, ok := c.take(4)
	return ok && binary.LittleEndian.Uint32(lock) == 0 && c.i == len(raw)
}

type withdrawalCursor struct {
	raw []byte
	i   int
}

func (c *withdrawalCursor) take(n int) ([]byte, bool) {
	if n < 0 || n > len(c.raw)-c.i {
		return nil, false
	}
	s := c.raw[c.i : c.i+n]
	c.i += n
	return s, true
}
func (c *withdrawalCursor) compact() (uint64, bool) {
	s, ok := c.take(1)
	if !ok {
		return 0, false
	}
	switch s[0] {
	case 253:
		b, k := c.take(2)
		if !k {
			return 0, false
		}
		n := uint64(binary.LittleEndian.Uint16(b))
		return n, n >= 253
	case 254:
		b, k := c.take(4)
		if !k {
			return 0, false
		}
		n := uint64(binary.LittleEndian.Uint32(b))
		return n, n > 65535
	case 255:
		b, k := c.take(8)
		if !k {
			return 0, false
		}
		n := binary.LittleEndian.Uint64(b)
		return n, n > math.MaxUint32
	default:
		return uint64(s[0]), true
	}
}
