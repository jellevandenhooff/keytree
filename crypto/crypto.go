package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/agl/ed25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/scrypt"

	"github.com/jellevandenhooff/keytree/encoding/base32"
)

type mustRandom struct{}

func (*mustRandom) Read(b []byte) (int, error) {
	n, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		log.Fatal(err)
	}
	return n, err
}

var mustRandomReader *mustRandom

func wrap(in []byte, pre string) string {
	return fmt.Sprintf("%s(%s)", pre, base32.EncodeToString(in))
}

func unwrapSlice(s, pre string) ([]byte, error) {
	if !strings.HasPrefix(s, pre+"(") || !strings.HasSuffix(s, ")") {
		return nil, errors.New("badly formatted")
	}
	s = strings.TrimPrefix(s, pre+"(")
	s = strings.TrimSuffix(s, ")")
	return base32.DecodeString(s)
}

func unwrapFixed(s, pre string, out []byte) error {
	bytes, err := unwrapSlice(s, pre)
	if err != nil {
		return err
	}

	if len(bytes) != len(out) {
		return errors.New("incorrect length")
	}
	copy(out, bytes)
	return nil
}

func generateBoxKeypair(reader io.Reader) (public string, private string) {
	publicKey, privateKey, err := box.GenerateKey(reader)
	if err != nil {
		log.Fatal(err)
	}
	return wrap(publicKey[:], "box-pub"),
		wrap(privateKey[:], "box-priv")
}

func GenerateRandomBoxKeypair() (public string, private string) {
	return generateBoxKeypair(mustRandomReader)
}

func generateEd25519Keypair(reader io.Reader) (public string, private string) {
	publicKey, privateKey, err := ed25519.GenerateKey(reader)
	if err != nil {
		log.Fatal(err)
	}
	return wrap(publicKey[:], "ed25519-pub"),
		wrap(privateKey[:], "ed25519-priv")
}

func GenerateRandomToken(n int) string {
	b := make([]byte, n)
	mustRandomReader.Read(b)
	return base32.EncodeToString(b)
}

func GenerateRandomEd25519Keypair() (public string, private string) {
	return generateEd25519Keypair(rand.Reader)
}

type Signable interface {
	SigningTypeName() string
	Hash() Hash
}

func GenerateEd25519KeypairFromSecret(secret, salt string) (public string, private string) {
	derived, err := scrypt.Key([]byte(secret), []byte(salt), 1<<14, 8, 1, 32)
	if err != nil {
		log.Fatal(err)
	}
	return generateEd25519Keypair(bytes.NewReader(derived))
}

func prepareforSigning(signable Signable) []byte {
	b := bytes.NewBuffer(nil)
	b.Write(signable.Hash().Bytes())
	b.Write([]byte(signable.SigningTypeName()))
	return b.Bytes()
}

func Sign(privateKey string, signable Signable) (string, error) {
	var key [ed25519.PrivateKeySize]byte
	if err := unwrapFixed(privateKey, "ed25519-priv", key[:]); err != nil {
		return "", err
	}

	sig := ed25519.Sign(&key, prepareforSigning(signable))
	return wrap(sig[:], "ed25519-sig"), nil
}

func Verify(publicKey string, signable Signable, signature string) error {
	var key [ed25519.PublicKeySize]byte
	if err := unwrapFixed(publicKey, "ed25519-pub", key[:]); err != nil {
		return err
	}

	var sig [ed25519.SignatureSize]byte
	if err := unwrapFixed(signature, "ed25519-sig", sig[:]); err != nil {
		return err
	}

	if !ed25519.Verify(&key, prepareforSigning(signable), &sig) {
		return errors.New("bad signature")
	}
	return nil
}

func Encrypt(message, public, private string) (string, error) {
	var nonce [24]byte
	mustRandomReader.Read(nonce[:])

	var pub [32]byte
	if err := unwrapFixed(public, "box-pub", pub[:]); err != nil {
		return "", err
	}

	var priv [32]byte
	if err := unwrapFixed(private, "box-priv", priv[:]); err != nil {
		return "", err
	}

	nonceAndSealed := box.Seal(nonce[:], []byte(message), &nonce, &pub, &priv)
	return wrap(nonceAndSealed, "box-box"), nil
}

func Decrypt(wrapped, public, private string) (string, error) {
	nonceAndSealed, err := unwrapSlice(wrapped, "box-box")
	if err != nil {
		return "", err
	}

	var nonce [24]byte
	if len(nonceAndSealed) < 24 {
		return "", errors.New("message missing nonce")
	}
	copy(nonce[:], nonceAndSealed[:24])
	sealed := nonceAndSealed[24:]

	var pub [32]byte
	if err := unwrapFixed(public, "box-pub", pub[:]); err != nil {
		return "", err
	}

	var priv [32]byte
	if err := unwrapFixed(private, "box-priv", priv[:]); err != nil {
		return "", err
	}

	message, ok := box.Open(nil, sealed, &nonce, &pub, &priv)
	if !ok {
		return "", errors.New("bad box")
	}
	return string(message), nil
}

type Signer struct {
	privateKey string
}

type testSignable struct {
	hash Hash
}

func (t *testSignable) SigningTypeName() string {
	return "test"
}

func (t *testSignable) Hash() Hash {
	return t.hash
}

func NewSigner(privateKey string) (*Signer, error) {
	if _, err := Sign(privateKey, &testSignable{}); err != nil {
		return nil, err
	}
	return &Signer{privateKey: privateKey}, nil
}

func (s *Signer) Sign(x Signable) string {
	// Must succeed because we tested this on start.
	signature, _ := Sign(s.privateKey, x)
	return signature
}
