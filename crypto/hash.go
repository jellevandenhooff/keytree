package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash"

	"github.com/jellevandenhooff/keytree/encoding/base32"
)

// Hash type

const HashLen = 32
const HashBits = 8 * HashLen

type Hash [HashLen]byte

func (h Hash) MarshalJSON() ([]byte, error) {
	return json.Marshal(base32.EncodeToString(h[:]))
}

func (h *Hash) UnmarshalJSON(data []byte) error {
	var buffer string
	if err := json.Unmarshal(data, &buffer); err != nil {
		return err
	}
	bytes, err := base32.DecodeString(buffer)
	if err != nil {
		return err
	}
	copy(h[:], bytes)
	return nil
}

func (h Hash) String() string {
	return base32.EncodeToString(h[:])
}

func FromString(s string) (Hash, error) {
	bytes, err := base32.DecodeString(s)
	if err != nil {
		return EmptyHash, err
	}
	if len(bytes) != HashLen {
		return EmptyHash, errors.New("wrong string length")
	}
	var h Hash
	copy(h[:], bytes)
	return h, nil
}

var EmptyHash = Hash{}
var LastHash Hash

func init() {
	for i := 0; i < HashLen; i++ {
		LastHash[i] = 255
	}
}

func (h Hash) Bytes() []byte {
	return h[:]
}

func (h *Hash) GetBit(idx int) int {
	return int((h[idx/8] >> uint(idx%8)) & 1)
}

func (h *Hash) SetBit(idx, value int) {
	if value == 0 {
		h[idx/8] &= ^(1 << uint8(idx%8))
	} else {
		h[idx/8] |= (1 << uint8(idx%8))
	}
}

// Hasher

type Hasher struct {
	underlying hash.Hash
}

func (h *Hasher) Write(data []byte) (int, error) {
	if n, _ := h.underlying.Write(data); n != len(data) {
		panic(h)
	}
	return len(data), nil
}

func (h *Hasher) WriteUint64(i uint64) {
	var buffer [8]byte
	binary.BigEndian.PutUint64(buffer[:], i)
	h.Write(buffer[:])
}

func (h *Hasher) WriteBool(b bool) {
	if b {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
}

func (h *Hasher) WriteString(s string) {
	h.WriteUint64(uint64(len(s)))
	h.Write([]byte(s))
}

func (h *Hasher) Sum() Hash {
	var hash Hash
	copy(hash[0:HashLen], h.underlying.Sum(nil))
	return hash
}

func NewHasher() *Hasher {
	return &Hasher{
		underlying: sha256.New(),
	}
}

// Utility functions for hashing

func HashString(s string) Hash {
	h := NewHasher()
	h.Write([]byte(s))
	return h.Sum()
}

func HashFromBytes(bytes []byte) Hash {
	var h Hash
	copy(h[:], bytes)
	return h
}

func CombineHashes(a, b Hash) Hash {
	if a == EmptyHash && b == EmptyHash {
		return EmptyHash
	}

	h := NewHasher()
	h.Write(a.Bytes())
	h.Write(b.Bytes())
	return h.Sum()
}

// Utility functions for using hashes as keys

func NextHash(h Hash) Hash {
	next := h
	for i := HashLen - 1; i >= 0; i-- {
		next[i] += 1
		if next[i] != 0 {
			break
		}
	}
	return next
}

func IsSmaller(a, b Hash) bool {
	for i := 0; i < HashLen; i++ {
		if a[i] > b[i] {
			return false
		}
		if a[i] < b[i] {
			return true
		}
	}
	return false
}

func MaxHash(a, b Hash) Hash {
	for i := 0; i < HashLen; i++ {
		if a[i] > b[i] {
			return a
		}
		if a[i] < b[i] {
			return b
		}
	}
	return a
}

func FirstDifference(a, b Hash) int {
	idx := 0
	for idx < HashBits && a.GetBit(idx) == b.GetBit(idx) {
		idx += 1
	}
	return idx
}
