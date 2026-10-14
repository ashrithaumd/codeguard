package auth

import "crypto/rand"

// crypto/rand for a token: the right source, never flagged.
func NewSessionToken() []byte {
	b := make([]byte, 32)
	// ok: codeguard-go-math-rand-secret
	rand.Read(b)
	return b
}
