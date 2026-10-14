package auth

import (
	"math/rand"
	"time"
)

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func NewSessionToken() string {
	b := make([]byte, 32)
	for i := range b {
		// ruleid: codeguard-go-math-rand-secret
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func generatePassword(n int) []byte {
	b := make([]byte, n)
	// ruleid: codeguard-go-math-rand-secret
	rand.Read(b)
	return b
}

type User struct{ ResetToken int64 }

func issue(u *User) {
	// ruleid: codeguard-go-math-rand-secret
	apiKey := rand.Int63()
	// ruleid: codeguard-go-math-rand-secret
	u.ResetToken = rand.Int63()
	// ruleid: codeguard-go-math-rand-secret
	var sessionID = rand.Uint64()
	// ruleid: codeguard-go-math-rand-secret
	inviteID := rand.Int63()
	// ruleid: codeguard-go-math-rand-secret
	deviceUUID := rand.Uint64()
	// ok: codeguard-go-math-rand-secret
	requestID := rand.Int63()
	_, _, _, _, _ = apiKey, sessionID, inviteID, deviceUUID, requestID
}

func Backoff(attempt int) time.Duration {
	base := time.Duration(1<<attempt) * 100 * time.Millisecond
	// ok: codeguard-go-math-rand-secret
	jitter := time.Duration(rand.Intn(100)) * time.Millisecond
	return base + jitter
}

func ShuffleDeck(deck []string) {
	// ok: codeguard-go-math-rand-secret
	rand.Shuffle(len(deck), func(i, j int) { deck[i], deck[j] = deck[j], deck[i] })
}

func pickColor(colors []string) string {
	// ok: codeguard-go-math-rand-secret
	idx := rand.Intn(len(colors))
	return colors[idx]
}
