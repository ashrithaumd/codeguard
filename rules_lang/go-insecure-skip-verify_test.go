package client

import "crypto/tls"

// A test's own client against a local test server: not production code.
func testConfig() *tls.Config {
	// ok: codeguard-go-tls-insecure-skip-verify
	return &tls.Config{InsecureSkipVerify: true}
}
