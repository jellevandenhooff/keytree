package rules

import (
	"errors"
	"strings"
)

const allowedKeyNameCharacters = "abcdefghijklmnopqrstuvwxyz1234567890-_:"

const allowedKeyValueCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890=-+_.,:@()/\\\"' \r\n"

func CheckKey(name, value string) error {
	for _, c := range name {
		if strings.IndexRune(allowedKeyNameCharacters, c) == -1 {
			return errors.New("bad key name character")
		}
	}

	for _, c := range value {
		if strings.IndexRune(allowedKeyValueCharacters, c) == -1 {
			return errors.New("bad key value character")
		}
	}

	return nil
}

func CheckName(name string) error {
	if err := CheckEmail(name); err != nil {
		return err
	}

	return nil
}

const allowedLocalCharacters = "abcdefghijklmnopqrstuvwxyz1234567890-_."
const allowedDomainCharacters = "abcdefghijklmnopqrstuvwxyz1234567890-_."

func CheckEmail(name string) error {
	if !strings.HasPrefix(name, "email:") {
		return nil
	}

	email := strings.TrimPrefix(name, "email:")

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return errors.New("expected one @")
	}

	local := parts[0]
	domain := parts[1]

	for _, c := range local {
		if strings.IndexRune(allowedLocalCharacters, c) == -1 {
			return errors.New("bad email character")
		}
	}

	for _, c := range domain {
		if strings.IndexRune(allowedDomainCharacters, c) == -1 {
			return errors.New("bad domain character")
		}
	}

	if len(domain) > 0 && domain[len(domain)-1] == '.' {
		return errors.New("domain must not end in .")
	}

	return nil
}
