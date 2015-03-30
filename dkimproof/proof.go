package dkimproof

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/jellevandenhooff/dkim"
	"github.com/jellevandenhooff/keytree/wire"
)

const mailCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-/=?^_`{|}~.@"

var mailAllowed [256]bool

func init() {
	for _, c := range []byte(mailCharacters) {
		mailAllowed[c] = true
	}
}

func extractFromAddress(email *dkim.VerifiedEmail) (string, error) {
	headers := email.ExtractHeader("from")
	if len(headers) != 1 {
		return "", errors.New("expected exactly one from header")
	}
	header := headers[0]

	var addresses []string

	var word []byte
	for _, c := range []byte(header) {
		if mailAllowed[c] {
			word = append(word, c)
		} else {
			if bytes.IndexByte(word, '@') != -1 {
				addresses = append(addresses, strings.ToLower(string(word)))
			}
			word = nil
		}
	}

	if len(addresses) != 1 {
		return "", errors.New("expected exactly one email address in from header")
	}
	address := addresses[0]

	if !strings.HasSuffix(address, "@"+email.Signature.Domain) {
		return "", errors.New("address in from header is not from signature's domain")
	}
	return address, nil
}

func CheckVerifiedEmail(email *dkim.VerifiedEmail, statement *wire.DKIMStatement) error {
	from, err := extractFromAddress(email)
	if err != nil {
		return fmt.Errorf("could next extract sender: %s", err)
	}
	if from != statement.Sender {
		return fmt.Errorf("incorrect sender '%s', expecting '%s'", from, statement.Sender)
	}

	subjects := email.ExtractHeader("subject")
	found := false
	for _, subject := range subjects {
		if strings.Contains(strings.ToLower(subject), strings.ToLower(statement.Token)) {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("missing token '%s' from subject", statement.Token)
	}

	return nil
}

func CheckPlainEmail(mail string, statement *wire.DKIMStatement, dnsClient dkim.DNSClient) error {
	email, err := dkim.ParseAndVerify(mail, dkim.HeadersOnly, dnsClient)
	if err != nil {
		return err
	}

	if err := CheckVerifiedEmail(email, statement); err != nil {
		return err
	}

	return nil
}
