package elgamal

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

// TestEncryptDecryptRoundTrip verifies basic encryption/decryption functionality
func TestEncryptDecryptRoundTrip(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	testCases := [][]byte{
		[]byte("Hello, World!"),
		[]byte("A"),
		[]byte("The quick brown fox jumps over the lazy dog"),
		{0x01, 0x02, 0x03, 0x04, 0x05},
		{0xFF, 0xFE, 0xFD},
	}

	for _, message := range testCases {
		ciphertext, err := priv.PublicKey.Encrypt(rand.Reader, message)
		if err != nil {
			t.Fatalf("Encrypt failed for message %v: %v", message, err)
		}

		plaintext, err := priv.Decrypt(rand.Reader, ciphertext, nil)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if !bytes.Equal(message, plaintext) {
			t.Errorf("Round-trip failed: got %v, want %v", plaintext, message)
		}
	}
}

// TestEncryptFunctionRoundTrip tests the standalone Encrypt/Decrypt functions
func TestEncryptFunctionRoundTrip(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	message := []byte("Test message")
	m := new(big.Int).SetBytes(message)

	c1, c2, err := Encrypt(rand.Reader, &priv.PublicKey, m)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(priv, c1, c2)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	decryptedBytes := decrypted.Bytes()

	if !bytes.Equal(message, decryptedBytes) {
		t.Errorf("Decryption failed: got %v, want %v", decryptedBytes, message)
	}
}

// TestEmptyMessage verifies handling of empty messages
func TestEmptyMessage(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	emptyMsg := []byte{}
	ciphertext, err := priv.PublicKey.Encrypt(rand.Reader, emptyMsg)
	if err != nil {
		t.Fatalf("Encrypt empty message failed: %v", err)
	}

	plaintext, err := priv.Decrypt(rand.Reader, ciphertext, nil)
	if err != nil {
		t.Fatalf("Decrypt empty message failed: %v", err)
	}

	if !bytes.Equal(emptyMsg, plaintext) {
		t.Errorf("Empty message round-trip failed: got %v, want %v", plaintext, emptyMsg)
	}
}

// TestMessageTooLarge verifies rejection of oversized messages
func TestMessageTooLarge(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Create a message larger than the modulus
	largeMsg := new(big.Int).Add(priv.P, big.NewInt(1))
	_, _, err = Encrypt(rand.Reader, &priv.PublicKey, largeMsg)
	if err == nil {
		t.Error("Expected error for message >= modulus, got nil")
	}
}

// TestInvalidKeySize verifies minimum key size enforcement
func TestInvalidKeySize(t *testing.T) {
	testCases := []int{256, 511, 0, -1}

	for _, size := range testCases {
		_, err := GenerateKey(rand.Reader, size)
		if err == nil {
			t.Errorf("Expected error for key size %d, got nil", size)
		}
	}

	// Verify 512 works
	_, err := GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Errorf("Key size 512 should work, got error: %v", err)
	}
}

// TestShortCiphertext verifies handling of malformed ciphertext
func TestShortCiphertext(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	testCases := [][]byte{
		{},
		{0x42},
	}

	for _, ct := range testCases {
		_, err := priv.Decrypt(rand.Reader, ct, nil)
		if err == nil {
			t.Errorf("Expected error for ciphertext length %d, got nil", len(ct))
		}
	}
}

// TestRandomization verifies that multiple encryptions produce different ciphertexts
func TestRandomization(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	message := []byte("Same message")

	ct1, _ := priv.PublicKey.Encrypt(rand.Reader, message)
	ct2, _ := priv.PublicKey.Encrypt(rand.Reader, message)

	if bytes.Equal(ct1, ct2) {
		t.Error("Multiple encryptions produced identical ciphertext (missing randomization)")
	}
}

// TestKeyGeneration verifies key generation produces valid keys
func TestKeyGeneration(t *testing.T) {
	for i := 0; i < 5; i++ {
		priv, err := GenerateKey(rand.Reader, 512)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		// Verify g = 2
		if priv.G.Cmp(big.NewInt(2)) != 0 {
			t.Errorf("Generator is not 2: got %s", priv.G.String())
		}

		// Verify y = g^x mod p
		computed := new(big.Int).Exp(priv.G, priv.X, priv.P)
		if computed.Cmp(priv.Y) != 0 {
			t.Error("Public key y != g^x mod p")
		}

		// Verify x in range [1, p-2]
		if priv.X.Cmp(big.NewInt(1)) < 0 {
			t.Error("Private key x < 1")
		}
		pMinus2 := new(big.Int).Sub(priv.P, big.NewInt(2))
		if priv.X.Cmp(pMinus2) > 0 {
			t.Error("Private key x > p-2")
		}
	}
}

// TestNilCiphertextComponents verifies nil handling in Decrypt
func TestNilCiphertextComponents(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Test with nil c1
	_, err = Decrypt(priv, nil, big.NewInt(100))
	if err == nil {
		t.Error("Expected error for nil c1")
	}

	// Test with nil c2
	_, err = Decrypt(priv, big.NewInt(100), nil)
	if err == nil {
		t.Error("Expected error for nil c2")
	}

	// Test with both nil
	_, err = Decrypt(priv, nil, nil)
	if err == nil {
		t.Error("Expected error for both nil")
	}
}

// TestBug1_NilPrivateKeyInDecrypt verifies Bug #1: nil PrivateKey handling
func TestBug1_NilPrivateKeyInDecrypt(t *testing.T) {
	// Should not panic when priv is nil
	var priv *PrivateKey = nil
	c1 := big.NewInt(100)
	c2 := big.NewInt(200)

	_, err := Decrypt(priv, c1, c2)
	if err == nil {
		t.Error("Expected error for nil PrivateKey")
	}
}

// TestBug2_ModInverseFailure verifies Bug #2: ModInverse failure handling
func TestBug2_ModInverseFailure(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// c1 = 0 will cause c1^x = 0, and ModInverse(0, p) returns nil
	c1 := big.NewInt(0)
	c2 := big.NewInt(100)

	// Should not panic when ModInverse returns nil
	_, err = Decrypt(priv, c1, c2)
	if err == nil {
		t.Error("Expected error for invalid ciphertext (c1=0)")
	}
}

// TestBug3_NegativeMessageValues verifies Bug #3: negative message validation
func TestBug3_NegativeMessageValues(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Negative message should be rejected
	negativeMsg := big.NewInt(-100)
	_, _, err = Encrypt(rand.Reader, &priv.PublicKey, negativeMsg)
	if err == nil {
		t.Error("Expected error for negative message, got nil")
	}
}

// TestBug4_NilPublicKeyInEncrypt verifies Bug #4: nil PublicKey handling
func TestBug4_NilPublicKeyInEncrypt(t *testing.T) {
	// Should not panic when pub is nil
	var pub *PublicKey = nil
	msg := big.NewInt(100)

	_, _, err := Encrypt(rand.Reader, pub, msg)
	if err == nil {
		t.Error("Expected error for nil PublicKey, got nil")
	}
}

// TestBug4_NilMessageInEncrypt verifies Bug #4: nil message handling
func TestBug4_NilMessageInEncrypt(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Should not panic when message is nil
	var msg *big.Int = nil

	_, _, err = Encrypt(rand.Reader, &priv.PublicKey, msg)
	if err == nil {
		t.Error("Expected error for nil message, got nil")
	}
}

// TestBug5_DecryptErrorPropagation verifies Bug #5: error propagation in Decrypt
func TestBug5_DecryptErrorPropagation(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Create invalid ciphertext (c1=0 will cause ModInverse to fail)
	modulusBytes := (priv.P.BitLen() + 7) / 8
	invalidCiphertext := make([]byte, modulusBytes*2)
	// c1 bytes are all zeros, c2 has some value
	for i := modulusBytes; i < len(invalidCiphertext); i++ {
		invalidCiphertext[i] = 0x42
	}

	// Decrypt should return an error for invalid ciphertext
	_, err = priv.Decrypt(rand.Reader, invalidCiphertext, nil)
	if err == nil {
		t.Error("Expected error for invalid ciphertext (c1=0), got nil")
	}
}
