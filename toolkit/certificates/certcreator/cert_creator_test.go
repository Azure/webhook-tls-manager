package certcreator

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"time"

	"github.com/Azure/webhook-tls-manager/toolkit/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CertCreator", func() {
	var (
		certCreator CertCreator
		privateKey  *rsa.PrivateKey
		publicKey   *rsa.PublicKey
		template    *x509.Certificate
	)

	BeforeEach(func() {
		certCreator = NewCertCreator()
		privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
		publicKey = &privateKey.PublicKey

		template = &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				Organization: []string{"Test Organization"},
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(365 * 24 * time.Hour),

			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
	})

	Describe("GenerateSN", func() {
		It("should return a big int", func() {
			sn, err := certCreator.GenerateSN()
			Expect(err).To(BeNil())
			Expect(sn).NotTo(BeNil())
		})
	})

	Describe("CreateCertificate", func() {
		It("should return a byte array", func() {
			parent := template
			rand := io.Reader(nil)
			cert, err := certCreator.CreateCertificate(rand, template, parent, publicKey, privateKey)
			Expect(err).To(BeNil())
			Expect(cert).NotTo(BeNil())
		})
	})

	Describe("ParseCertificate", func() {
		It("should return a certificate", func() {
			derBytes, _ := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
			cert, err := certCreator.ParseCertificate(derBytes)
			Expect(err).To(BeNil())
			Expect(cert).NotTo(BeNil())
		})
	})

	Describe("CreateCertificateWithPublicKey", func() {
		It("should return a certificate", func() {
			ctx := log.NewLogger(3).WithLogger(context.TODO())
			cert, err := certCreator.CreateCertificateWithPublicKey(ctx, template, publicKey, template, privateKey)
			Expect(err).To(BeNil())
			Expect(cert).NotTo(BeNil())
		})
	})
})
