package crypto

import "bytes"
import "testing"

func TestSigningRoundtrip(t *testing.T) {
	public, private := GenerateRandomEd25519Keypair()

	a := testSignable{
		hash: HashString("hello, world!"),
	}

	b := testSignable{
		hash: HashString("goodbye, world!"),
	}

	sigA, err := Sign(private, &a)
	if err != nil {
		t.Errorf("unexpected error signing: %s", err)
	}

	sigB, _ := Sign(private, &b)

	if err := Verify(public, &a, sigA); err != nil {
		t.Errorf("unexpected error verifying: %s", err)
	}

	if err := Verify(public, &a, sigB); err == nil || err.Error() != "bad signature" {
		t.Errorf("expected bad signature; got %s", err)
	}
}

var a = []byte{1, 2, 3}
var b = []byte{4, 5, 6, 7}

func TestWrapBase32(t *testing.T) {
	wrapA := wrap(a, "test-foo")
	expA := "test-foo(04106)"
	if wrapA != expA {
		t.Errorf("expected %s; got %s", expA, wrapA)
	}
}

func TestWrapUnwrapRoundtrip(t *testing.T) {
	wrapA := wrap(a, "test-foo")

	unwrapA, err := unwrapSlice(wrapA, "test-foo")
	if err != nil {
		t.Errorf("unexpected error unwrapping: %s", err)
	}

	if bytes.Compare(unwrapA, a) != 0 {
		t.Errorf("unwrap-wrap did not roundtrip; got %v, expected %v", unwrapA, a)
	}

	if _, err := unwrapSlice(wrapA, "test-bar"); err == nil {
		t.Errorf("unexpected success unwrapping: %s", err)
	}
}
