package base32

import (
	"encoding/base32"
	"errors"
	"strings"
)

// drop the following letters:
// i - can be confused with 1,j
// l - can be confused with 1
// o - can be confused with 0
// u - can be confused with v
const encodeKeytree = "0123456789abcdefghjkmnpqrstvwxyz"

var KeytreeEncoding = base32.NewEncoding(encodeKeytree)

func EncodeToString(src []byte) string {
	s := KeytreeEncoding.EncodeToString(src)
	return strings.TrimRight(s, "=")
}

func DecodeString(s string) ([]byte, error) {
	pad := strings.Repeat("=", (8-len(s)%8)%8)
	ss := s + pad
	dst, err := KeytreeEncoding.DecodeString(ss)
	if err != nil {
		return nil, err
	}
	if KeytreeEncoding.EncodeToString(dst) != ss {
		return dst, errors.New("uncanonical base32 input")
	}
	return dst, nil
}
