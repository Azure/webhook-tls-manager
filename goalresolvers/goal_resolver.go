package goalresolvers

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"github.com/Azure/webhook-tls-manager/config"
	"github.com/Azure/webhook-tls-manager/consts"
	"github.com/Azure/webhook-tls-manager/toolkit/certificates"
	"github.com/Azure/webhook-tls-manager/toolkit/certificates/certcreator"
	"github.com/Azure/webhook-tls-manager/toolkit/certificates/certgenerator"
	"github.com/Azure/webhook-tls-manager/toolkit/certificates/certoperator"
	"github.com/Azure/webhook-tls-manager/toolkit/log"
	"github.com/Azure/webhook-tls-manager/utils"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type CertificateData struct {
	CaCertPem     []byte
	CaKeyPem      []byte
	ServerCertPem []byte
	ServerKeyPem  []byte
}

type WebhookTlsManagerGoal struct {
	CertData                     *CertificateData
	IsKubeSystemNamespaceBlocked bool
	IsWebhookTlsManagerEnabled   bool
}

type webhookTlsManagerGoalResolver struct {
	certOperator                 certoperator.CertOperator
	kubeClient                   kubernetes.Interface
	isKubeSystemNamespaceBlocked bool
	IsWebhookTlsManagerEnabled   bool
	namespace                    string
}

func (g *webhookTlsManagerGoalResolver) shouldRotateCert(ctx context.Context) (bool, *error) {

	logger := log.MustGetLogger(ctx)

	secret, getErr := g.kubeClient.CoreV1().Secrets(g.namespace).Get(ctx, utils.SecretName(), metav1.GetOptions{})
	if k8serrors.IsNotFound(getErr) {
		logger.Infof("secret %s not exists", utils.SecretName())
		return true, nil
	}
	if getErr != nil {
		logger.Errorf("get secret %s failed. error: %s", utils.SecretName(), getErr)
		return false, &getErr
	}
	logger.Infof("secret %s exists", utils.SecretName())
	if v, exist := secret.ObjectMeta.Labels[consts.ManagedLabelKey]; exist && v == consts.ManagedLabelValue {
		logger.Infof("found secret %s managed by aks. checking expiration date.", utils.SecretName())
		expired, err := certificates.IsPEMCertificateExpired(logger, string(secret.Data["serverCert.pem"]), utils.SecretName(), time.Now().AddDate(0, 1, 0))
		if err != nil {
			logger.Errorf("failed to check cert %s. error: %s", utils.SecretName(), err)
			return false, &err
		}
		if expired {
			logger.Infof("cert expired.")
			return true, nil
		}
		logger.Infof("cert valid.")
		return false, nil
	}
	logger.Warningf("found secret %s is not managed by AKS.", utils.SecretName())
	return false, nil
}

func (g *webhookTlsManagerGoalResolver) generateCertificates(ctx context.Context) (*CertificateData, *error) {
	logger := log.MustGetLogger(ctx)
	now := time.Now().UTC()
	notBefore := now.Add(-certificates.ClockSkewDuration)
	notAfter := now.AddDate(config.AppConfig.CaValidityYears, 0, 0)
	caCsr := &x509.Certificate{
		Subject:               pkix.Name{CommonName: utils.CACertificateCommonName()},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		IsCA:                  true,
		DNSNames:              []string{utils.CACertificateCommonName()},
	}

	caCert, caCertPem, caKey, caKeyPem, rerr := g.certOperator.CreateSelfSignedCertificateKeyPair(ctx, caCsr)
	if rerr != nil {
		logger.Errorf("generateCertificates generate ca certs and key failed: %s", rerr.Error())
		return &CertificateData{}, &rerr.RawError
	}

	notAfter = now.AddDate(config.AppConfig.ServerValidityYears, 0, 0)

	serverCsr := &x509.Certificate{
		Subject:               pkix.Name{CommonName: utils.ServerCertificateCommonName()},
		Issuer:                pkix.Name{CommonName: utils.CACertificateCommonName()},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{utils.ServerCertificateCommonName()},
	}

	serverCertPem, serverKeyPem, rerr := g.certOperator.CreateCertificateKeyPair(ctx, serverCsr, caCert, caKey)
	if rerr != nil {
		logger.Errorf("generateCertificates generate server certs and key failed: %s", rerr.Error())
		return &CertificateData{}, &rerr.RawError
	}

	logger.Info("new cert generated")
	return &CertificateData{
		CaCertPem:     []byte(caCertPem),
		CaKeyPem:      []byte(caKeyPem),
		ServerCertPem: []byte(serverCertPem),
		ServerKeyPem:  []byte(serverKeyPem),
	}, nil
}

func NewWebhookTlsManagerGoalResolver(ctx context.Context, kubeClient kubernetes.Interface, isKubeSystemNamespaceBlocked bool, IsWebhookTlsManagerEnabled bool, namespace string) WebhookTlsManagerGoalResolverInterface {
	logger := log.MustGetLogger(ctx)
	logger.Infof("NewWebhookTlsManagerGoalResolver: isKubeSystemNamespaceBlocked=%v, IsWebhookTlsManagerEnabled=%v", isKubeSystemNamespaceBlocked, IsWebhookTlsManagerEnabled)
	generator := certgenerator.NewCertGenerator(certcreator.NewCertCreator())
	operator := certoperator.NewCertOperator(generator)
	return &webhookTlsManagerGoalResolver{
		certOperator:                 operator,
		kubeClient:                   kubeClient,
		isKubeSystemNamespaceBlocked: isKubeSystemNamespaceBlocked,
		IsWebhookTlsManagerEnabled:   IsWebhookTlsManagerEnabled,
		namespace:                    namespace,
	}
}

func (g *webhookTlsManagerGoalResolver) Resolve(ctx context.Context) (*WebhookTlsManagerGoal, *error) {
	logger := log.MustGetLogger(ctx)
	logger.Infof("Resolve: isKubeSystemNamespaceBlocked=%v, IsWebhookTlsManagerEnabled=%v", g.isKubeSystemNamespaceBlocked, g.IsWebhookTlsManagerEnabled)
	goal := &WebhookTlsManagerGoal{
		IsKubeSystemNamespaceBlocked: g.isKubeSystemNamespaceBlocked,
		IsWebhookTlsManagerEnabled:   g.IsWebhookTlsManagerEnabled,
	}

	rotateCert, cerr := g.shouldRotateCert(ctx)
	if cerr != nil {
		logger.Errorf("Failed to check cert expiration date. error: %s", *cerr)
		return nil, cerr
	}
	if !rotateCert {
		logger.Info("no need to rotate cert.")
		goal.CertData = nil
	} else {
		data, cerr := g.generateCertificates(ctx)
		if cerr != nil {
			logger.Errorf("generateCertificates. error: %s", *cerr)
			return nil, cerr
		}
		goal.CertData = data
	}
	return goal, nil
}
