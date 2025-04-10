package certcreator

//go:generate mockgen -destination=mock_cert_creator/cert_creator.go -package=mock_cert_creator github.com/Azure/webhook-tls-manager/toolkit/certificates/certcreator CertCreator

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"math/big"

	"k8s.io/legacy-cloud-providers/azure/retry"
)

type CertCreator interface {
	CreateCertificateWithPublicKey(ctx context.Context, csr *x509.Certificate, publicKey *rsa.PublicKey, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *retry.Error)
	GenerateSN() (*big.Int, error)
	CreateCertificate(rand io.Reader, template, parent *x509.Certificate, publicKey interface{}, privateKey interface{}) ([]byte, error)
	ParseCertificate(derBytes []byte) (*x509.Certificate, error)
}
