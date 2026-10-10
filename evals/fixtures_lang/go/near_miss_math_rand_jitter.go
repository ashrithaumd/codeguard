// Near miss: math/rand, but only for retry jitter, never for anything secret.
package retry

import (
	"math/rand"
	"time"
)

func Backoff(attempt int) time.Duration {
	base := time.Duration(1<<attempt) * 100 * time.Millisecond
	jitter := time.Duration(rand.Intn(100)) * time.Millisecond
	return base + jitter
}
