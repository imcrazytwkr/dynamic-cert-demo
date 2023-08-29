package services

import (
	"context"
	"crypto/tls"
)

type CertStorageService interface {
	GetCertificate(ctx context.Context, hostname string) (*tls.Certificate, error)
}
