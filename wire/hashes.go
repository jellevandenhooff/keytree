package wire

import (
	"encoding/json"
	"errors"
	"strconv"

	"github.com/jellevandenhooff/keytree/crypto"
)

type Hashes [crypto.HashBits]crypto.Hash

func (h *Hashes) MarshalJSON() ([]byte, error) {
	m := make(map[string]crypto.Hash)
	for k, v := range *h {
		if v != crypto.EmptyHash {
			m[strconv.Itoa(k)] = v
		}
	}
	return json.Marshal(m)
}

func (h *Hashes) UnmarshalJSON(data []byte) error {
	var m map[string]crypto.Hash
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	for k, v := range m {
		idx, err := strconv.Atoi(k)
		if err != nil {
			return err
		}
		if idx < 0 || idx >= crypto.HashBits {
			return errors.New("idx out of range")
		}
		h[idx] = v
	}
	return nil
}
