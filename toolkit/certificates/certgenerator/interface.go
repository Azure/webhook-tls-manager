package certgenerator

import (
	"context"
	"crypto/rsa"
	"crypto/x509"

	"k8s.io/legacy-cloud-providers/azure/retry"
)

type CertGenerator interface {
	CreateSelfSignedCertificateKeyPair(ctx context.Context, csr *x509.Certificate) (*x509.Certificate, *rsa.PrivateKey, *retry.Error)
	CreateCertificateKeyPair(ctx context.Context, csr *x509.Certificate, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, *retry.Error)
	CreateCertificate(ctx context.Context, csr *x509.Certificate, key *rsa.PrivateKey, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *retry.Error)
}
