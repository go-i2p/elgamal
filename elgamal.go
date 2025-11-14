package elgamal

import (
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// PublicKey represents an ElGamal public key
type PublicKey struct {
	P *big.Int // prime modulus
	G *big.Int // generator
	Y *big.Int // public key value
}

// Encrypt encrypts a message using ElGamal encryption for the public key
func (p *PublicKey) Encrypt(randReader io.Reader, msg []byte) (ciphertext []byte, err error) {
	if randReader == nil {
		randReader = rand.Reader
	}
	// Convert msg to big.Int
	m := new(big.Int).SetBytes(msg)

	// Encrypt the message
	c1, c2, err := Encrypt(randReader, p, m)
	if err != nil {
		return nil, err
	}

	// Concatenate c1 and c2 into a single byte slice
	c1Bytes := c1.Bytes()
	c2Bytes := c2.Bytes()

	ciphertext = append(c1Bytes, c2Bytes...)
	return ciphertext, nil
}

// PrivateKey represents an ElGamal private key
type PrivateKey struct {
	PublicKey
	X *big.Int // private key value
}

// Decrypt implements crypto.Decrypter.
func (p *PrivateKey) Decrypt(randReader io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	if randReader == nil {
		randReader = rand.Reader
	}
	// Split msg into c1 and c2
	if len(msg) < 2 {
		return nil, errors.New("ciphertext too short")
	}

	// Determine split point (half of message)
	mid := len(msg) / 2
	c1 := new(big.Int).SetBytes(msg[:mid])
	c2 := new(big.Int).SetBytes(msg[mid:])

	// Decrypt and convert result to bytes
	plainInt := Decrypt(p, c1, c2)
	return plainInt.Bytes(), nil
}

// Public implements crypto.Signer.
func (p *PrivateKey) Public() crypto.PublicKey {
	return &p.PublicKey
}

// GenerateKey generates a new ElGamal key pair
func GenerateKey(random io.Reader, bitSize int) (*PrivateKey, error) {
	if bitSize < 512 {
		return nil, errors.New("key size must be at least 512 bits")
	}

	// Generate a prime p
	p, err := rand.Prime(random, bitSize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate prime: %w", err)
	}

	// Use 2 as generator (simple but works for most primes)
	g := big.NewInt(2)

	// Generate private key x in range [1, p-2]
	pMinus2 := new(big.Int).Sub(p, big.NewInt(2))
	x, err := rand.Int(random, pMinus2)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	x.Add(x, big.NewInt(1)) // ensure x >= 1

	// Calculate public key y = g^x mod p
	y := new(big.Int).Exp(g, x, p)

	return &PrivateKey{
		PublicKey: PublicKey{P: p, G: g, Y: y},
		X:         x,
	}, nil
}

// Encrypt encrypts a message using ElGamal encryption
func Encrypt(random io.Reader, pub *PublicKey, message *big.Int) (*big.Int, *big.Int, error) {
	if message.Cmp(pub.P) >= 0 {
		return nil, nil, errors.New("message too large for key size")
	}

	// Generate random k in range [1, p-2]
	pMinus2 := new(big.Int).Sub(pub.P, big.NewInt(2))
	k, err := rand.Int(random, pMinus2)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random k: %w", err)
	}
	k.Add(k, big.NewInt(1))

	// Calculate c1 = g^k mod p
	c1 := new(big.Int).Exp(pub.G, k, pub.P)

	// Calculate c2 = m * y^k mod p
	yk := new(big.Int).Exp(pub.Y, k, pub.P)
	c2 := new(big.Int).Mul(message, yk)
	c2.Mod(c2, pub.P)

	return c1, c2, nil
}

// Decrypt decrypts a ciphertext using ElGamal decryption
func Decrypt(priv *PrivateKey, c1, c2 *big.Int) *big.Int {
	// Validate inputs to prevent nil pointer dereference
	if c1 == nil || c2 == nil {
		// Return zero on invalid input rather than panicking
		// This maintains the function signature while handling the error case
		return big.NewInt(0)
	}

	// Calculate c1^x mod p
	c1x := new(big.Int).Exp(c1, priv.X, priv.P)

	// Calculate modular inverse of c1^x
	inv := new(big.Int).ModInverse(c1x, priv.P)

	// Calculate message = c2 * inv mod p
	message := new(big.Int).Mul(c2, inv)
	message.Mod(message, priv.P)

	return message
}
