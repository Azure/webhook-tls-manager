package certgenerator

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/Azure/webhook-tls-manager/toolkit/certificates/certcreator"
	"github.com/Azure/webhook-tls-manager/toolkit/keypool"
	"github.com/Azure/webhook-tls-manager/toolkit/log"
	"github.com/sirupsen/logrus"
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
)

type certificateGeneratorImp struct {
	keypool     keypool.KeyPool
	certCreator certcreator.CertCreator
}

func NewCertGenerator(keypool keypool.KeyPool) CertGenerator {
	return &certificateGeneratorImp{
		keypool:     keypool,
		certCreator: certcreator.NewCertCreator(),
	}
}

func (c *certificateGeneratorImp) CreateSelfSignedCertificateKeyPair(ctx context.Context, csr *x509.Certificate) (*x509.Certificate, *rsa.PrivateKey, *retry.Error) {
	if csr == nil {
		return nil, nil, retry.NewError(false, fmt.Errorf("certificate signing request is nil"))
	}

	logger := log.MustGetLogger(ctx)

	privateKey, err := c.ensureHasKey(ctx, logger)
	if err != nil {
		logger.Errorf("ensure Key failed: %s", err)
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

	privateKey, err := c.ensureHasKey(ctx, logger)
	if err != nil {
		logger.Errorf("ensureKey failed: %s", err)
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

func (c *certificateGeneratorImp) ensureHasKey(
	ctx context.Context,
	logger *logrus.Entry) (*rsa.PrivateKey, error) {
	privateKey, err := c.keypool.GetKey(ctx, *logger)
	if err != nil {
		// Whatever it is an empty pool or not, we call GenerateSingleKey directly and apply a fixed type retry.
		// If GenerateSingleKey succeeds, then return the key.
		// If retrying GenerateSingleKey fails, then return error.
		if c.keypool.CurrentSize() != 0 {
			logger.Errorf("GetKey failed: %s even keypool is not empty", err)
		}

		count := 0

		var res *rsa.PrivateKey
		var err error
		for count <= KeyRetryCount {
			privateKey, err = c.keypool.GenerateSingleKey(ctx, *logger)
			if err != nil {
				logger.Errorf("one time GenerateSingleKey failed: %s", err)
				count++
			} else {
				res = privateKey
			}
			time.Sleep(KeyRetryTimeout)
		}

		if res != nil {
			var errMsg string
			if count == KeyRetryCount {
				errMsg = fmt.Sprintf("tried %d times GenerateSingleKey, but failed: %s", KeyRetryCount, err)
			} else {
				errMsg = fmt.Sprintf("tried %d times GenerateSingleKey, timeout %d seconds. Failed: %s", count, int(KeyRetryTimeout.Seconds()), err)
			}
			logger.Errorf(errMsg)
			return nil, fmt.Errorf(errMsg)
		}
	}

	return privateKey, nil
}
