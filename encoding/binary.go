package encoding

import (
	"encoding/binary"
)

func EncodeBEUint64(n uint64) []byte {
	buffer := make([]byte, 8)
	binary.BigEndian.PutUint64(buffer, n)
	return buffer
}

func DecodeBEUint64(bytes []byte) uint64 {
	return binary.BigEndian.Uint64(bytes)
}
