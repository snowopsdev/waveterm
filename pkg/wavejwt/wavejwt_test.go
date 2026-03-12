package wavejwt

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func snapshotKeys() (ed25519.PublicKey, ed25519.PrivateKey) {
	globalLock.Lock()
	defer globalLock.Unlock()

	var pubCopy ed25519.PublicKey
	if len(publicKey) > 0 {
		pubCopy = make([]byte, len(publicKey))
		copy(pubCopy, publicKey)
	}

	var privCopy ed25519.PrivateKey
	if len(privateKey) > 0 {
		privCopy = make([]byte, len(privateKey))
		copy(privCopy, privateKey)
	}

	return pubCopy, privCopy
}

func restoreKeys(pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	globalLock.Lock()
	defer globalLock.Unlock()
	publicKey = pub
	privateKey = priv
}

func TestSetPublicKeyCopiesInput(t *testing.T) {
	origPub, origPriv := snapshotKeys()
	t.Cleanup(func() { restoreKeys(origPub, origPriv) })

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := append([]byte(nil), priv.Public().(ed25519.PublicKey)...)

	if err := SetPublicKey(pub); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}

	pub[0] ^= 0xFF

	got := GetPublicKey()
	if bytes.Equal(got, pub) {
		t.Fatalf("public key changed after mutating caller input")
	}
}

func TestGetPublicKeyReturnsCopy(t *testing.T) {
	origPub, origPriv := snapshotKeys()
	t.Cleanup(func() { restoreKeys(origPub, origPriv) })

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if err := SetPublicKey(pub); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}

	first := GetPublicKey()
	if len(first) == 0 {
		t.Fatalf("expected public key to be set")
	}
	first[0] ^= 0xFF

	second := GetPublicKey()
	if bytes.Equal(first, second) {
		t.Fatalf("mutating returned public key should not affect internal state")
	}
	if !bytes.Equal(second, pub) {
		t.Fatalf("stored public key changed unexpectedly")
	}
}

func TestSetPrivateKeyCopiesInputViaSignValidate(t *testing.T) {
	origPub, origPriv := snapshotKeys()
	t.Cleanup(func() { restoreKeys(origPub, origPriv) })

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	privInput := append([]byte(nil), priv...)
	if err := SetPrivateKey(privInput); err != nil {
		t.Fatalf("SetPrivateKey: %v", err)
	}
	if err := SetPublicKey(pub); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}

	for i := range privInput {
		privInput[i] = 0
	}

	token, err := Sign(&WaveJwtClaims{Sock: "sock-1"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	claims, err := ValidateAndExtract(token)
	if err != nil {
		t.Fatalf("ValidateAndExtract: %v", err)
	}
	if claims.Sock != "sock-1" {
		t.Fatalf("unexpected claim sock: %q", claims.Sock)
	}
}
