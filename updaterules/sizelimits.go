package updaterules

import (
	"errors"

	"github.com/jellevandenhooff/keytree/wire"
)

const MaxNameLength = 1024
const MaxKeys = 64
const MaxKeyNameLength = 64
const MaxKeyValueLength = 4096
const MaxTotalValueLength = 8192

func SizeCheckEntry(entry *wire.Entry) error {
	if len(entry.Name) > MaxNameLength {
		return errors.New("bad name; len must be <= MaxNameLength")
	}
	if len(entry.Keys) > MaxKeys {
		return errors.New("bad keys; len must be <= MaxKeys")
	}

	total := 0
	for name, value := range entry.Keys {
		if len(name) > MaxKeyNameLength {
			return errors.New("bad key name; len must be <= MaxKeyNameLength")
		}
		if len(value) > MaxKeyValueLength {
			return errors.New("bad key value; len must be <= MaxKeyValueLength")
		}
		total += len(value)
	}
	if total > MaxTotalValueLength {
		return errors.New("bad keys; total value len must be <= MaxTotalValueLength")
	}

	return nil
}

const MaxSignatures = 4
const MaxSignatureNameLength = 128
const MaxSignatureValueLength = 128
const MaxDKIMSignatureValueLength = 4096

func SizeCheckSignatures(signatures map[string]string) error {
	if len(signatures) > MaxSignatures {
		return errors.New("bad signatures; len must be <= MaxSignatures")
	}

	for name, value := range signatures {
		if len(name) > MaxSignatureNameLength {
			return errors.New("bad signature name; len must be <= MaxSignatureNameLength")
		}
		if name != "dkim" {
			if len(value) > MaxSignatureValueLength {
				return errors.New("bad signature value; len must be <= MaxSignatureValueLength")
			}
		} else {
			if len(value) > MaxDKIMSignatureValueLength {
				return errors.New("bad dkim signature value; len must be <= MaxDKIMSignatureValueLength")
			}
		}
	}

	return nil
}
