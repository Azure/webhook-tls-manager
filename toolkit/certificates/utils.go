package certificates

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/Azure/webhook-tls-manager/log"
)

func PemToPrivateKey(ctx context.Context, raw string) (*rsa.PrivateKey, error) {
	kpb, _ := pem.Decode([]byte(raw))
	if kpb == nil {
		log.GetLogger(ctx).Errorf(ctx, "Decode returns nil")
		return nil, errors.New("The raw pem is not a valid PEM formatted block")
	}
	return x509.ParsePKCS1PrivateKey(kpb.Bytes)
}

func PemToCertificate(ctx context.Context, raw string) (*x509.Certificate, error) {
	cpb, _ := pem.Decode([]byte(raw))
	if cpb == nil {
		log.GetLogger(ctx).Errorf(ctx, "Decode returns nil")
		return nil, errors.New("The raw pem is not a valid PEM formatted block")
	}
	return x509.ParseCertificate(cpb.Bytes)
}

func CertificateToPem(ctx context.Context, cert *x509.Certificate) ([]byte, error) {
	derBytes := cert.Raw
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	pemBuffer := bytes.Buffer{}
	err := encodeFunc(&pemBuffer, pemBlock)
	if err != nil {
		log.GetLogger(ctx).Errorf(ctx, "pem encode() return error %s", err)
		return nil, err
	}

	return pemBuffer.Bytes(), nil
}

func PrivateKeyToPem(ctx context.Context, privateKey *rsa.PrivateKey) ([]byte, error) {
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	pemBuffer := bytes.Buffer{}
	err := encodeFunc(&pemBuffer, pemBlock)
	if err != nil {
		log.GetLogger(ctx).Errorf(ctx, "pem encode() return error %s", err)
		return nil, err
	}

	return pemBuffer.Bytes(), nil
}
