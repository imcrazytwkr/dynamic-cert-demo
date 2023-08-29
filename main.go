package main

import (
	"crypto/rsa"
	"crypto/tls"
	"log"

	vault "github.com/hashicorp/vault/api"
	"github.com/imcrazytwkr/dynamic-cert-demo/services/certstore"
)

const MAX_LRU_ENTRIES = 10

func main() {
	config := vault.DefaultConfig()
	config.Address = "http://127.0.0.1:8200"

	client, err := vault.NewClient(config)
	if err != nil {
		log.Panicf("unable to initialize Vault client: %v\n", err)
	}

	// Based on Hashicorp's tutorial. Don't use in production!
	client.SetToken("dev-only-token")

	pair := client.KVv2("secret")
	store := certstore.NewVaultCertificateStorageService(pair, "http-certs/")
	service := certstore.NewCachingCertificateStorageService(store, MAX_LRU_ENTRIES)

	tlsConfig := certstore.WrapTLSConfig(nil, service)
	cert, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.org"})
	if err != nil {
		log.Panicf("failed to retrieve example certificate: %v\n", err)
	}

	log.Println("Blocks:")
	for _, block := range cert.Certificate {
		log.Println(string(block))
	}

	privateKey, ok := cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		log.Panicln("failed to parse private key")
	}

	log.Println("Key:")
	log.Panicln(privateKey.D.Bytes())
}
