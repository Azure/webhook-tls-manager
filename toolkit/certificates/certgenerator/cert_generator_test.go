package certgenerator

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"time"

	"github.com/Azure/webhook-tls-manager/toolkit/certificates/certcreator/mock_cert_creator"
	"github.com/Azure/webhook-tls-manager/toolkit/log"
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/legacy-cloud-providers/azure/retry"
)

var _ = Describe("CertGenerator", func() {
	var (
		ctx             context.Context
		mockCertCreator *mock_cert_creator.MockCertCreator
		mockCtrl        *gomock.Controller
		certGenerator   CertGenerator
	)

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		mockCertCreator = mock_cert_creator.NewMockCertCreator(mockCtrl)
		certGenerator = NewCertGenerator(mockCertCreator)
		ctx = log.NewLogger(3).WithLogger(context.TODO())
	})
	Describe("CreateSelfSignedCertificateKeyPair", func() {
		It("CreateSelfSignedCertificateKeyPair nil certificate input", func() {
			_, _, err := certGenerator.CreateSelfSignedCertificateKeyPair(ctx, nil)
			Expect(err).ToNot(BeNil())
			Expect(err.Error().Error()).To(ContainSubstring("certificate signing request is nil"))
		})

		It("CreateSelfSignedCertificateKeyPair failed CreateCertificateWithPublicKey", func() {
			csr := &x509.Certificate{}
			rerr := retry.Error{
				Retriable:      false,
				RetryAfter:     time.Time{},
				HTTPStatusCode: 0,
				RawError:       errors.New("createCertificate failed"),
			}
			mockCertCreator.EXPECT().CreateCertificateWithPublicKey(ctx, csr, gomock.Any(), csr, gomock.Any()).Return(nil, &rerr)
			_, _, err := certGenerator.CreateSelfSignedCertificateKeyPair(ctx, csr)
			Expect(err).ToNot(BeNil())
			Expect(err.Error().Error()).To(ContainSubstring("createCertificate failed"))
		})

		It("CreateSelfSignedCertificateKeyPair succeed", func() {
			csr := &x509.Certificate{
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
			mockCertCreator.EXPECT().CreateCertificateWithPublicKey(ctx, csr, gomock.Any(), csr, gomock.Any()).Return(nil, nil)
			_, _, err := certGenerator.CreateSelfSignedCertificateKeyPair(ctx, csr)
			Expect(err).To(BeNil())
		})
	})

	Describe("CreateCertificateKeyPair", func() {
		It("CreateCertificateKeyPair nil certificate input", func() {
			_, _, err := certGenerator.CreateCertificateKeyPair(ctx, nil, nil, nil)
			Expect(err).ToNot(BeNil())
			Expect(err.Error().Error()).To(ContainSubstring("certificate signing request is nil"))
		})

		It("CreateCertificateKeyPair failed CreateCertificateWithPublicKey", func() {
			csr := &x509.Certificate{}
			caCert := &x509.Certificate{}
			caKey := &rsa.PrivateKey{}

			rerr := retry.Error{
				Retriable:      false,
				RetryAfter:     time.Time{},
				HTTPStatusCode: 0,
				RawError:       errors.New("CreateCertificateWithPublicKey failed"),
			}
			mockCertCreator.EXPECT().CreateCertificateWithPublicKey(ctx, csr, gomock.Any(), caCert, caKey).Return(nil, &rerr)

			_, _, err := certGenerator.CreateCertificateKeyPair(ctx, csr, caCert, caKey)
			Expect(err).ToNot(BeNil())
			Expect(err.Error().Error()).To(ContainSubstring("CreateCertificateWithPublicKey failed"))
		})

		It("CreateCertificateKeyPair succeed", func() {
			csr := &x509.Certificate{
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
			caCert := &x509.Certificate{}
			caKey := &rsa.PrivateKey{}

			mockCertCreator.EXPECT().CreateCertificateWithPublicKey(ctx, csr, gomock.Any(), caCert, caKey).Return(nil, nil)

			_, _, err := certGenerator.CreateCertificateKeyPair(ctx, csr, caCert, caKey)
			Expect(err).To(BeNil())
		})
	})

	Describe("CreateCertificate", func() {
		It("CreateCertificate nil certificate input", func() {
			privateKey := &rsa.PrivateKey{}
			_, err := certGenerator.CreateCertificate(ctx, nil, privateKey, nil, nil)
			Expect(err).ToNot(BeNil())
			Expect(err.Error().Error()).To(ContainSubstring("certificate signing request is nil"))
		})

		It("CreateCertificate nil private key input", func() {
			csr := &x509.Certificate{}
			_, err := certGenerator.CreateCertificate(ctx, csr, nil, nil, nil)
			Expect(err).ToNot(BeNil())
			Expect(err.Error().Error()).To(ContainSubstring("private key is nil"))
		})

		It("CreateCertificate failed CreateCertificateWithPublicKey", func() {
			csr := &x509.Certificate{}
			privateKey := &rsa.PrivateKey{}
			rerr := retry.Error{
				Retriable:      false,
				RetryAfter:     time.Time{},
				HTTPStatusCode: 0,
				RawError:       errors.New("CreateCertificateWithPublicKey failed"),
			}
			mockCertCreator.EXPECT().CreateCertificateWithPublicKey(ctx, csr, gomock.Any(), csr, privateKey).Return(nil, &rerr)
			_, err := certGenerator.CreateCertificate(ctx, csr, privateKey, csr, privateKey)
			Expect(err).ToNot(BeNil())
			Expect(err.Error().Error()).To(ContainSubstring("CreateCertificateWithPublicKey failed"))
		})

		It("CreateCertificate succeed", func() {
			csr := &x509.Certificate{
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
			privateKey := &rsa.PrivateKey{}

			mockCertCreator.EXPECT().CreateCertificateWithPublicKey(ctx, csr, gomock.Any(), csr, privateKey).Return(nil, nil)
			_, err := certGenerator.CreateCertificate(ctx, csr, privateKey, csr, privateKey)
			Expect(err).To(BeNil())
		})
	})
})
