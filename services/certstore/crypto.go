package certstore

import (
	"crypto/tls"
	"crypto/x509"
)

// For performance reasons this whole method should have been replaces with
// a reimplementation of tls.X509KeyPair function but since this is just
// an example, we are okay with just parsing leaf cert for the second time
func parseFullX509(certBlock []byte, keyBlock []byte) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certBlock, keyBlock)
	if err != nil {
		return nil, err
	}

	if cert.Leaf != nil {
		// Google devs decided to attach parsed cert so we can relax
		return &cert, nil
	}

	// Current (Go 1.19) default behaviour requires us to do some legwork
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	return &cert, nil
}
