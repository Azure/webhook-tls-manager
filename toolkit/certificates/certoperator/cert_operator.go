package certoperator

import (
	"context"
	"crypto/rsa"
	"crypto/x509"

	"github.com/Azure/webhook-tls-manager/log"
	"k8s.io/legacy-cloud-providers/azure/retry"
)

func (o *certOperator) getCertKeyAsPem(
	ctx context.Context,
	cert *x509.Certificate,
	key *rsa.PrivateKey) (string, string, error) {
	certBytes, err := o.certificateToPemFunc(ctx, cert)
	if err != nil {
		log.MustGetLogger(ctx).Errorf(ctx, "CertificateToPem failed: %s", err)
		return "", "", err
	}

	keyBytes, err := o.privateKeyToPemFunc(ctx, key)
	if err != nil {
		log.MustGetLogger(ctx).Errorf(ctx, "PrivateKeyToPem failed: %s", err)
		return "", "", err
	}

	return string(certBytes), string(keyBytes), nil
}

func (o *certOperator) CreateSelfSignedCertificateKeyPair(
	ctx context.Context,
	csr *x509.Certificate) (*x509.Certificate, string, *rsa.PrivateKey, string, *retry.Error) {

	cert, key, rerr := o.certGenerator.CreateSelfSignedCertificateKeyPair(ctx, csr)
	if rerr != nil {
		log.MustGetLogger(ctx).Errorf(ctx, "CreateSelfSignedCertificateKeyPair failed: %v", rerr)
		return nil, "", nil, "", rerr
	}
	certPem, keyPem, err := o.getCertKeyAsPem(ctx, cert, key)
	if err != nil {
		log.MustGetLogger(ctx).Errorf(ctx, "certKeyToPem failed: %s", err)
		return nil, "", nil, "", retry.NewError(false, err)
	}
	log.MustGetLogger(ctx).Infof(ctx, "self signed certificate '%v' is generated successfully", csr.Subject.CommonName)
	return cert, certPem, key, keyPem, nil
}

func (o *certOperator) CreateCertificateKeyPair(
	ctx context.Context,
	csr *x509.Certificate,
	caCert *x509.Certificate,
	caKey *rsa.PrivateKey) (string, string, *retry.Error) {
	cert, key, rerr := o.certGenerator.CreateCertificateKeyPair(ctx, csr, caCert, caKey)
	if rerr != nil {
		log.MustGetLogger(ctx).Errorf(ctx, "CreateCertificateKeyPair failed: %v", rerr)
		return "", "", rerr
	}
	certPem, keyPem, err := o.getCertKeyAsPem(ctx, cert, key)
	if err != nil {
		log.MustGetLogger(ctx).Errorf(ctx, "getCertKeyAsPem failed: %s", err)
		return "", "", retry.NewError(false, err)
	}
	log.MustGetLogger(ctx).Infof(ctx, "certificate %v is generated successfully", csr.Subject.CommonName)
	return certPem, keyPem, nil
}
