package certstore

import (
	"context"
	"crypto/tls"
	"log"
	"time"

	"github.com/imcrazytwkr/dynamic-cert-demo/services"
	"github.com/mailgun/groupcache/v2/lru"
)

type cachingCertStorageService struct {
	store services.CertStorageService
	cache *lru.Cache
}

func NewCachingCertificateStorageService(store services.CertStorageService, entries int) services.CertStorageService {
	return &cachingCertStorageService{
		store: store,
		cache: lru.New(entries),
	}
}

func (s *cachingCertStorageService) GetCertificate(ctx context.Context, hostname string) (*tls.Certificate, error) {
	cached, ok := s.cache.Get(hostname)
	if ok {
		return cached.(*tls.Certificate), nil
	}

	cert, err := s.store.GetCertificate(ctx, hostname)
	if err != nil {
		return nil, err
	}

	if cert.Leaf.NotAfter.IsZero() {
		// Invalid cert
		return nil, nil
	}

	expires := cert.Leaf.NotAfter.AddDate(0, 0, -SOFT_LIMIT_EXPIRY_DAYS)
	if expires.After(time.Now()) {
		s.cache.Add(hostname, cert, expires)
		return cert, nil
	}

	log.Printf("[WARN] cert for %q expires at %s!\n", hostname, expires.Format(time.RFC3339))

	// Only caching certs that have at least 24 hours to live
	expires = cert.Leaf.NotAfter.AddDate(0, 0, -HARD_LIMIT_EXPIRY_DATS)
	if expires.After(time.Now()) {
		s.cache.Add(hostname, cert, expires)
	} else {
		log.Printf("[ERR] cert for %q expires at %s!\n", hostname, expires.Format(time.RFC3339))
	}

	return cert, nil
}
