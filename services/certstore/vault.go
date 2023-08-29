package certstore

import (
	"context"
	"crypto/tls"

	vault "github.com/hashicorp/vault/api"
	"github.com/imcrazytwkr/dynamic-cert-demo/services"
	mapstruct "github.com/mitchellh/mapstructure"
)

type vaultCertStorageService struct {
	prefix string
	client *vault.KVv2
}

func NewVaultCertificateStorageService(client *vault.KVv2, prefix string) services.CertStorageService {
	return &vaultCertStorageService{
		prefix: prefix,
		client: client,
	}
}

func (s *vaultCertStorageService) GetCertificate(ctx context.Context, hostname string) (*tls.Certificate, error) {
	secret, err := s.client.Get(ctx, s.prefix+hostname)
	if err != nil {
		return nil, err
	}

	var certData StorageCertificate
	err = mapstruct.Decode(secret.Data, &certData)
	if err != nil {
		return nil, err
	}

	return parseFullX509(certData.CAChainBytes(), certData.KeyBytes())
}
