package client

import (
	"crypto/tls"
	"net/http"
)

func Insecure() *http.Client {
	// ruleid: codeguard-go-tls-insecure-skip-verify
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	return &http.Client{Transport: tr}
}

func InsecureLater() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	// ruleid: codeguard-go-tls-insecure-skip-verify
	cfg.InsecureSkipVerify = true
	return cfg
}

func InsecureValue() tls.Config {
	// ruleid: codeguard-go-tls-insecure-skip-verify
	return tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
}

func Verified() *http.Client {
	// ok: codeguard-go-tls-insecure-skip-verify
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: false}}
	return &http.Client{Transport: tr}
}

func Default() *tls.Config {
	// ok: codeguard-go-tls-insecure-skip-verify
	return &tls.Config{MinVersion: tls.VersionTLS12}
}
