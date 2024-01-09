package certoperator

import (
	"context"
	"crypto/rsa"
	"crypto/x509"

	"k8s.io/legacy-cloud-providers/azure/retry"
)

type CertOperator interface {
	certificateToPem(ctx context.Context, cert *x509.Certificate) ([]byte, error)
	privateKeyToPem(ctx context.Context, privateKey *rsa.PrivateKey) ([]byte, error)
	pemToCertificate(ctx context.Context, raw string) (*x509.Certificate, error)
	pemToPrivateKey(ctx context.Context, raw string) (*rsa.PrivateKey, error)
	CreateCertificateKeyPair(ctx context.Context,
		csr *x509.Certificate,
		caCert *x509.Certificate,
		caKey *rsa.PrivateKey) (string, string, *retry.Error)
	CreateSelfSignedCertificateKeyPair(
		ctx context.Context,
		csr *x509.Certificate) (*x509.Certificate, string, *rsa.PrivateKey, string, *retry.Error)
}
