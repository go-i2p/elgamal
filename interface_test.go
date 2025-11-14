package elgamal

// Ensure that the elgamal package implements the standard cryptographic interfaces.

import (
	"crypto"
	"testing"
)

func TestElGamalImplementsCryptoInterfaces(t *testing.T) {
	var _ crypto.PublicKey = &PublicKey{}
	var _ crypto.Decrypter = &PrivateKey{}
}
