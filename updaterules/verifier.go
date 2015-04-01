package updaterules

import (
	"errors"
	"flag"
	"strings"

	"github.com/jellevandenhooff/dkim"

	"github.com/jellevandenhooff/keytree/crypto"
	"github.com/jellevandenhooff/keytree/dkimproof"
	"github.com/jellevandenhooff/keytree/encoding/base32"
	"github.com/jellevandenhooff/keytree/wire"
)

const OneDayInSeconds = 24 * 60 * 60
const RecoverWaitTime = 4 * OneDayInSeconds

const TokenBits = 128
const TokenLen = TokenBits / 8

var allowTestNames = flag.Bool("allow-test-names", true, "Allow names of the form 'test:' without proof of ownership.")

type Verifier struct {
	dnsClient dkim.DNSClient
}

func NewVerifier(dnsClient dkim.DNSClient) *Verifier {
	return &Verifier{
		dnsClient: dnsClient,
	}
}

func TokenForEntry(entry *wire.Entry) string {
	return base32.EncodeToString(entry.Hash().Bytes()[:TokenLen])
}

func (v *Verifier) CheckProofOfOwnership(update *wire.SignedEntry) error {
	name := update.Entry.Name

	token := TokenForEntry(update.Entry)

	if strings.HasPrefix(name, "email:") {
		signature, found := update.Signatures["dkim"]
		if !found {
			return errors.New("no dkim signature")
		}
		email := strings.TrimPrefix(name, "email:")

		statement := &wire.DKIMStatement{
			Sender: email,
			Token:  token,
		}

		return dkimproof.CheckPlainEmail(signature, statement, v.dnsClient)
	} else if strings.HasPrefix(name, "test:") && *allowTestNames {
		// accept test names without complaining!
		signature, found := update.Signatures["test"]
		if !found {
			return errors.New("no test signature")
		}
		if signature != token {
			return errors.New("bad test signature")
		}
		return nil
	} else {
		return errors.New("unknown name type")
	}
}

type Window struct {
	Start, End uint64
}

func (w *Window) Contains(t uint64) bool {
	return w.Start <= t && t < w.End
}

type changeInfo struct {
	validSignatures          map[string]bool
	changedKeys              map[string]bool
	hadKeytreeKey            bool
	hasValidKeytreeSignature bool
	hasChangedKeytreeKey     bool
	hasValidOwnershipProof   bool
}

func (v *Verifier) getChangeInfo(old *wire.Entry, update *wire.SignedEntry) *changeInfo {
	validSignatures := make(map[string]bool)
	for name, key := range old.Keys {
		signature, found := update.Signatures[key]
		if !found {
			continue
		}
		if err := crypto.Verify(key, update.Entry, signature); err != nil {
			continue
		}
		validSignatures[name] = true
	}

	changedKeys := make(map[string]bool)
	for name, key := range old.Keys {
		if update.Entry.Keys[name] != key {
			changedKeys[name] = true
		}
	}
	for name, key := range update.Entry.Keys {
		if old.Keys[name] != key {
			changedKeys[name] = true
		}
	}

	hadKeytreeKey := false
	for name := range old.Keys {
		if strings.HasPrefix(name, "keytree:") {
			hadKeytreeKey = true
		}
	}

	hasValidKeytreeSignature := false
	for name := range validSignatures {
		if strings.HasPrefix(name, "keytree:") {
			hasValidKeytreeSignature = true
		}
	}

	hasChangedKeytreeKey := false
	for name := range changedKeys {
		if strings.HasPrefix(name, "keytree:") {
			hasChangedKeytreeKey = true
		}
	}

	hasValidOwnershipProof := v.CheckProofOfOwnership(update) == nil

	return &changeInfo{
		validSignatures:          validSignatures,
		changedKeys:              changedKeys,
		hadKeytreeKey:            hadKeytreeKey,
		hasValidKeytreeSignature: hasValidKeytreeSignature,
		hasChangedKeytreeKey:     hasChangedKeytreeKey,
		hasValidOwnershipProof:   hasValidOwnershipProof,
	}
}

var baseEntry = &wire.Entry{
	Name:       "",
	Timestamp:  0,
	InRecovery: false,
	Keys:       map[string]string{},
}

func (v *Verifier) VerifyUpdate(old *wire.Entry, update *wire.SignedEntry, now Window) error {
	if old == nil {
		old = baseEntry
	}

	if !now.Contains(update.Entry.Timestamp) {
		return errors.New("bad timestamp; must be in window")
	}

	if old.Timestamp >= update.Entry.Timestamp {
		return errors.New("bad timestamp; must be > old timestamp")
	}

	info := v.getChangeInfo(old, update)

	overrideSignatureRequirement := false

	if old.InRecovery {
		if !info.hasValidOwnershipProof {
			return errors.New("need valid proof of ownership if record in recovery")
		}

		if old.Timestamp+RecoverWaitTime < update.Entry.Timestamp {
			overrideSignatureRequirement = true
		}
	}

	if update.Entry.InRecovery {
		if !info.hasValidOwnershipProof {
			return errors.New("need valid proof of ownership to put record in recovery")
		}

		if len(info.changedKeys) > 0 {
			return errors.New("can't change keys if record is in recovery")
		}
	}

	if !info.hadKeytreeKey {
		if !info.hasValidOwnershipProof {
			return errors.New("record without keytree keys needs valid proof of ownership")
		}

		overrideSignatureRequirement = true
	}

	if len(info.changedKeys) > 0 && !info.hasValidKeytreeSignature && !overrideSignatureRequirement {
		return errors.New("need valid signature without valid override")
	}

	if info.hasChangedKeytreeKey && !info.validSignatures["keytree:recovery"] && !info.hasValidOwnershipProof {
		return errors.New("need proof of ownership to change a keytree key")
	}

	return nil
}

func CheckEntry(entry *wire.Entry) error {
	if err := SizeCheckEntry(entry); err != nil {
		return err
	}

	if err := CheckName(entry.Name); err != nil {
		return err
	}

	for name, value := range entry.Keys {
		if err := CheckKey(name, value); err != nil {
			return err
		}
	}

	return nil
}

func CheckUpdate(update *wire.SignedEntry) error {
	if err := CheckEntry(update.Entry); err != nil {
		return err
	}

	if err := SizeCheckSignatures(update.Signatures); err != nil {
		return err
	}

	return nil
}
