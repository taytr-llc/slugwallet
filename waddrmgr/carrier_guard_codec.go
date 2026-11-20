package waddrmgr

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
)

func carrierGuardDecode(raw []byte, cap int, target any) error {
	if len(raw) == 0 || len(raw) > cap {
		return ErrHostedAllocationCorrupt
	}
	// Walk bounded typed containers before decoding any DTO slices.
	walkDecoder := json.NewDecoder(bytes.NewReader(raw))
	walkDecoder.UseNumber()
	tokens, objects := 0, 0
	var walk func(int, string) error
	walk = func(depth int, key string) error {
		if depth > 16 {
			return ErrHostedAllocationCorrupt
		}
		tokens++
		if tokens > 262144 {
			return ErrHostedAllocationCapacity
		}
		token, e := walkDecoder.Token()
		if e != nil {
			return ErrHostedAllocationCorrupt
		}
		switch x := token.(type) {
		case json.Delim:
			switch x {
			case '{':
				objects++
				if objects > 8192 {
					return ErrHostedAllocationCapacity
				}
				seen := map[string]bool{}
				for walkDecoder.More() {
					k, e := walkDecoder.Token()
					s, ok := k.(string)
					if e != nil || !ok || len(s) > 64 || seen[s] {
						return ErrHostedAllocationCorrupt
					}
					seen[s] = true
					if e = walk(depth+1, s); e != nil {
						return e
					}
				}
				end, e := walkDecoder.Token()
				if e != nil || end != json.Delim('}') {
					return ErrHostedAllocationCorrupt
				}
			case '[':
				limit, exact := 0, 0
				switch key {
				case "inputs":
					limit = 16
				case "invalid_indices":
					limit = 127
				case "cursors", "cursors_before", "cursors_after", "activation_cursors":
					limit = 8
					exact = 8
				case "accounts":
					limit = 4
					exact = 4
				default:
					return ErrHostedAllocationCorrupt
				}
				n := 0
				for walkDecoder.More() {
					n++
					if n > limit {
						return ErrHostedAllocationCapacity
					}
					if e = walk(depth+1, ""); e != nil {
						return e
					}
				}
				end, e := walkDecoder.Token()
				if e != nil || end != json.Delim(']') || exact != 0 && n != exact {
					return ErrHostedAllocationCorrupt
				}
			default:
				return ErrHostedAllocationCorrupt
			}
		case string:
			if len(x) > 8192 {
				return ErrHostedAllocationCapacity
			}
			for i := range x {
				if x[i] > 127 {
					return ErrHostedAllocationCorrupt
				}
			}
		case json.Number:
			n, e := strconv.ParseInt(string(x), 10, 64)
			if e != nil || strconv.FormatInt(n, 10) != string(x) {
				return ErrHostedAllocationCorrupt
			}
		case bool:
		case nil:
			return ErrHostedAllocationCorrupt
		default:
			return ErrHostedAllocationCorrupt
		}
		return nil
	}
	if e := walk(0, ""); e != nil {
		return e
	}
	if _, e := walkDecoder.Token(); e != io.EOF {
		return ErrHostedAllocationCorrupt
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(target); e != nil {
		return ErrHostedAllocationCorrupt
	}
	canonical, e := json.Marshal(target)
	if e != nil || !bytes.Equal(canonical, raw) {
		return ErrHostedAllocationCorrupt
	}
	return nil
}
