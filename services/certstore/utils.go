package certstore

import (
	"crypto/tls"

	"github.com/imcrazytwkr/dynamic-cert-demo/services"
)

func WrapTLSConfig(config *tls.Config, service services.CertStorageService) *tls.Config {
	if config == nil {
		config = &tls.Config{}
	}

	config.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return service.GetCertificate(chi.Context(), chi.ServerName)
	}

	return config
}
