package pia

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
)

// ImageCAPath is the operator-facing copy of the pinned CA.
const ImageCAPath = "/usr/share/transmission-openvpn/pia/ca.rsa.4096.crt"

//go:embed testdata/ca.rsa.4096.crt
var caPEM []byte

// CA is the public PIA RSA 4096 PEM.
func CA() []byte {
	return caPEM
}

// CAPool is the only trust anchor for the port-forward gateway.
func CAPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("pia: pinned CA did not parse")
	}
	return pool, nil
}

func parseCA() (*x509.Certificate, error) {
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return nil, fmt.Errorf("pia: pinned CA is not PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
