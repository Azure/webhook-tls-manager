package certificates

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/Azure/webhook-tls-manager/toolkit/log"
)

// IsPEMCertificateExpired check if a pem certificate expired
func IsPEMCertificateExpired(ctx context.Context, encodedCert, certName string, expirationTime time.Time) (bool, error) {
	logger := log.MustGetLogger(ctx)
	if encodedCert == "" {
		logger.Errorf(ctx, "cert is empty")
		return false, fmt.Errorf("empty cert of %s", certName)
	}

	block, leftover := pem.Decode([]byte(encodedCert))
	if len(leftover) > 0 {
		logger.Warningf(ctx, "leftover string in cert of %s", certName)
	}

	if block == nil || len(block.Bytes) < 1 {
		return false, fmt.Errorf("failed to pem decode cert of %s", certName)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse cert of %s, error: %s", certName, err)
	}

	logger.Infof(ctx, "cert.NotAfter: %s", cert.NotAfter.String())
	if cert.NotAfter.Before(expirationTime) {
		return true, nil
	}

	return false, nil
}

func GetPEMCertificateString(expirationTime time.Time) (string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return "", err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: expirationTime.Add(-time.Hour * 24 * 30),
		NotAfter:  expirationTime,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", err
	}

	out := &bytes.Buffer{}
	err = pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return "", err
	}
	return out.String(), nil
}
