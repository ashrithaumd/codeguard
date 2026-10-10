// Planted: a password-reset token drawn from math/rand.
package auth

import (
	"encoding/hex"
	"math/rand"
)

func NewResetToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
