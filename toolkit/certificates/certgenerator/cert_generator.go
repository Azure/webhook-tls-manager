package certgenerator

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/Azure/webhook-tls-manager/toolkit/certificates/certcreator"
	"github.com/Azure/webhook-tls-manager/toolkit/log"
	"k8s.io/legacy-cloud-providers/azure/retry"
)

const (
	// DefaultValidityYears is the duration for regular certificates, SSL etc. 2 years.
	// WARNING: this is used everywhere
	DefaultValidityYears = 2

	// CaValidityYears is the duration for CA certificates. 30 years.
	// WARNING: this is used everywhere
	CaValidityYears = 30

	// ClockSkewDuration is the allowed clock skews.
	ClockSkewDuration = time.Minute * 10

	// KeyRetryCount is the number of retries for certificate generation.
	KeyRetryCount    = 3
	KeyRetryInterval = time.Microsecond * 5
	KeyRetryTimeout  = time.Second * 10
	KeySize          = 4096
)

type certificateGeneratorImp struct {
	certCreator certcreator.CertCreator
}

func NewCertGenerator(certCreator certcreator.CertCreator) CertGenerator {
	return &certificateGeneratorImp{
		certCreator: certCreator,
	}
}

func (c *certificateGeneratorImp) CreateSelfSignedCertificateKeyPair(ctx context.Context, csr *x509.Certificate) (*x509.Certificate, *rsa.PrivateKey, *retry.Error) {
	if csr == nil {
		return nil, nil, retry.NewError(false, fmt.Errorf("certificate signing request is nil"))
	}

	logger := log.MustGetLogger(ctx)

	privateKey, err := rsa.GenerateKey(rand.Reader, KeySize)
	// privateKey, err := c.ensureHasKey(ctx, logger)
	if err != nil {
		logger.Errorf("rsa.GenerateKeyfailed: %s", err)
		return nil, nil, retry.NewError(true, err)
	}

	certificate, rerr := c.certCreator.CreateCertificateWithPublicKey(ctx, csr, &privateKey.PublicKey, csr, privateKey)
	if rerr != nil {
		logger.Errorf("createCertificate failed: %+v", rerr)
		return nil, nil, rerr
	}

	return certificate, privateKey, nil
}

func (c *certificateGeneratorImp) CreateCertificateKeyPair(ctx context.Context, csr *x509.Certificate, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, *retry.Error) {
	if csr == nil {
		return nil, nil, retry.NewError(false, fmt.Errorf("certificate signing request is nil"))
	}

	logger := log.MustGetLogger(ctx)

	privateKey, err := rsa.GenerateKey(rand.Reader, KeySize)
	if err != nil {
		logger.Errorf("rsa.GenerateKey failed: %s", err)
		return nil, nil, retry.NewError(true, err)
	}

	certificate, rerr := c.certCreator.CreateCertificateWithPublicKey(ctx, csr, &privateKey.PublicKey, caCert, caKey)
	if rerr != nil {
		logger.Errorf("createCertificate failed: %+v", rerr)
		return nil, nil, rerr
	}

	return certificate, privateKey, nil
}

func (c *certificateGeneratorImp) CreateCertificate(ctx context.Context, csr *x509.Certificate, privateKey *rsa.PrivateKey, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *retry.Error) {
	if privateKey == nil {
		return nil, retry.NewError(false, fmt.Errorf("private key is nil"))
	}
	if csr == nil {
		return nil, retry.NewError(false, fmt.Errorf("certificate signing request is nil"))
	}

	return c.certCreator.CreateCertificateWithPublicKey(ctx, csr, &privateKey.PublicKey, caCert, caKey)
}
