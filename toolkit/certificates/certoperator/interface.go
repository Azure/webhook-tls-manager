package certoperator

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
)

type Interface interface {
	CreateSelfSignedCertificateKeyPair(
		ctx context.Context,
		csr *x509.Certificate) (*x509.Certificate, string, *rsa.PrivateKey, string, *error)
	CreateCertificateKeyPair(
		ctx context.Context,
		csr *x509.Certificate,
		caCert *x509.Certificate,
		caKey *rsa.PrivateKey) (string, string, *error)
	certificateToPem(ctx context.Context, cert *x509.Certificate) ([]byte, error)
	privateKeyToPem(ctx context.Context, privateKey *rsa.PrivateKey) ([]byte, error)
	pemToCertificate(ctx context.Context, raw string) (*x509.Certificate, error)
	pemToPrivateKey(ctx context.Context, raw string) (*rsa.PrivateKey, error)
}
