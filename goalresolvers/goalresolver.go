package goalresolvers

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"github.com/Azure/webhook-tls-manager/consts"
	"github.com/Azure/webhook-tls-manager/toolkit/certificates"
	"github.com/Azure/webhook-tls-manager/toolkit/certificates/certgenerator"
	"github.com/Azure/webhook-tls-manager/toolkit/certificates/certoperator"
	"github.com/Azure/webhook-tls-manager/toolkit/keypool"
	"github.com/Azure/webhook-tls-manager/toolkit/log"

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
	IsVPAEnabled                 bool
}

type webhookTlsManagerGoalResolver struct {
	certOperator                 certoperator.CertOperator
	kubeClient                   kubernetes.Interface
	isKubeSystemNamespaceBlocked bool
	IsVPAEnabled                 bool
}

func (g *webhookTlsManagerGoalResolver) shouldRotateCert(ctx context.Context) (bool, *error) {

	logger := log.MustGetLogger(ctx)

	secret, getErr := g.kubeClient.CoreV1().Secrets(metav1.NamespaceSystem).Get(ctx, consts.SecretName, metav1.GetOptions{})
	if k8serrors.IsNotFound(getErr) {
		logger.Infof("secret %s not exists", consts.SecretName)
		return true, nil
	}
	if getErr != nil {
		logger.Errorf("get secret %s failed. error: %s", consts.SecretName, getErr)
		return false, &getErr
	}
	logger.Infof("secret %s exists", consts.SecretName)
	if v, exist := secret.ObjectMeta.Labels[consts.ManagedLabelKey]; exist && v == consts.ManagedLabelValue {
		logger.Infof("found secret %s managed by aks. checking expiration date.", consts.SecretName)
		expired, err := certificates.IsPEMCertificateExpired(logger, string(secret.Data["serverCert.pem"]), consts.SecretName, time.Now().AddDate(0, 1, 0))
		if err != nil {
			logger.Errorf("failed to check cert %s. error: %s", consts.SecretName, err)
			return false, &err
		}
		if expired {
			logger.Infof("cert expired.")
			return true, nil
		}
		logger.Infof("cert valid.")
		return false, nil
	}
	logger.Warningf("found secret %s is not managed by AKS.", consts.SecretName)
	return false, nil
}

func (g *webhookTlsManagerGoalResolver) generateOverlayVpaCertificates(ctx context.Context) (*CertificateData, *error) {
	logger := log.MustGetLogger(ctx)
	now := time.Now().UTC()
	notBefore := now.Add(-certificates.ClockSkewDuration)
	notAfter := now.AddDate(certificates.CaValidityYears, 0, 0)
	caCsr := &x509.Certificate{
		Subject:               pkix.Name{CommonName: consts.CommonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		IsCA:                  true,
		DNSNames:              []string{consts.CommonName},
	}

	caCert, caCertPem, caKey, caKeyPem, rerr := g.certOperator.CreateSelfSignedCertificateKeyPair(ctx, caCsr)
	if rerr != nil {
		logger.Errorf("generateOverlayVpaCertificates generate ca certs and key failed: %s", rerr)
		return &CertificateData{}, &rerr.RawError
	}

	notAfter = now.AddDate(certificates.DefaultValidityYears, 0, 0)

	serverCsr := &x509.Certificate{
		Subject:               pkix.Name{CommonName: consts.ServerCommonName},
		Issuer:                pkix.Name{CommonName: consts.CommonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{consts.ServerCommonName},
	}

	serverCertPem, serverKeyPem, rerr := g.certOperator.CreateCertificateKeyPair(ctx, serverCsr, caCert, caKey)
	if rerr != nil {
		logger.Errorf("generateOverlayVpaCertificates generate server certs and key failed: %s", rerr)
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

func NewWebhookTlsManagerGoalResolver(ctx context.Context, kubeClient kubernetes.Interface, isKubeSystemNamespaceBlocked bool, IsVPAEnabled bool) WebhookTlsManagerGoalResolverInterface {
	logger := log.MustGetLogger(ctx)
	logger.Infof("NewWebhookTlsManagerGoalResolver: isKubeSystemNamespaceBlocked=%v, IsVPAEnabled=%v", isKubeSystemNamespaceBlocked, IsVPAEnabled)
	kp := keypool.NewKeyPool(2, func() int64 { return int64(1) })
	timeout := 20 * time.Second
	entryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err := kp.BlockUntilCount(entryCtx, *logger, 2)
	if err != nil {
		logger.Warningf("keypool block until count fails. error: %s", err)
	}
	generator := certgenerator.NewCertGenerator(*kp)
	operator := certoperator.NewCertOperator(generator)
	return &webhookTlsManagerGoalResolver{
		certOperator:                 operator,
		kubeClient:                   kubeClient,
		isKubeSystemNamespaceBlocked: isKubeSystemNamespaceBlocked,
		IsVPAEnabled:                 IsVPAEnabled,
	}
}

func (g *webhookTlsManagerGoalResolver) Resolve(ctx context.Context) (*WebhookTlsManagerGoal, *error) {
	logger := log.MustGetLogger(ctx)
	logger.Infof("Resolve: isKubeSystemNamespaceBlocked=%v, IsVPAEnabled=%v", g.isKubeSystemNamespaceBlocked, g.IsVPAEnabled)
	goal := &WebhookTlsManagerGoal{
		IsKubeSystemNamespaceBlocked: g.isKubeSystemNamespaceBlocked,
		IsVPAEnabled:                 g.IsVPAEnabled,
	}

	rotateCert, cerr := g.shouldRotateCert(ctx)
	if cerr != nil {
		logger.Errorf("Failed to check cert expiration date. error: %s", cerr)
		return nil, cerr
	}
	if !rotateCert {
		logger.Info("no need to rotate cert.")
		goal.CertData = nil
	} else {
		data, cerr := g.generateOverlayVpaCertificates(ctx)
		if cerr != nil {
			logger.Errorf("generateOverlayVpaCertificates. error: %s", cerr)
			return nil, cerr
		}
		goal.CertData = data
	}
	return goal, nil
}
