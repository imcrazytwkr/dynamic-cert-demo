package certstore

type StorageCertificate struct {
	CAChain string `mapstructure:"ca_chain"`
	Key     string `mapstructure:"key"`
}

func (s *StorageCertificate) CAChainBytes() []byte {
	return []byte(s.CAChain)
}

func (s *StorageCertificate) KeyBytes() []byte {
	return []byte(s.Key)
}
