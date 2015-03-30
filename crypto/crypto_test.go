package crypto

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
