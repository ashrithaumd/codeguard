// Planted: TLS certificate verification turned off for an outbound client.
package client

import (
	"crypto/tls"
	"net/http"
)

func New() *http.Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	return &http.Client{Transport: tr}
}
