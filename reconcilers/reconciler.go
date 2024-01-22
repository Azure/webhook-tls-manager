package reconcilers

import (
	"bytes"
	"context"
	"errors"
	"time"

	admissionregistration "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/Azure/webhook-tls-manager/consts"
	"github.com/Azure/webhook-tls-manager/goalresolvers"
	"github.com/Azure/webhook-tls-manager/metrics"
	"github.com/Azure/webhook-tls-manager/toolkit/log"
)

const (
	retryCount    = 10
	retryInterval = 5 * time.Second
	retryTimeout  = 15 * time.Second
)

var webhookTimeOutSeconds = int32(30)

func shouldUpdateWebhook(ctx context.Context, webhookConfig *admissionregistration.MutatingWebhookConfiguration,
	isKubeSystemNamespaceBlocked bool, clientset kubernetes.Interface) (bool, *error) {
	logger := log.MustGetLogger(ctx)

	admissionEnforcerDisabled, labelExist := webhookConfig.Labels[consts.AdmissionEnforcerDisabledLabel]
	//If the value of admissionEnforcerDisabled is false, the kube-system namespace is blocked.
	if isKubeSystemNamespaceBlocked {
		logger.Info("kube-system should be blocked")
		if labelExist && admissionEnforcerDisabled == consts.AdmissionEnforcerDisabledValue {
			return true, nil
		}
	} else {
		logger.Info("kube-system should be unblocked")
		if !labelExist || admissionEnforcerDisabled != consts.AdmissionEnforcerDisabledValue {
			logger.Info("update webhookConfig for label")
			return true, nil
		}
	}

	secret, getErr := clientset.CoreV1().Secrets(metav1.NamespaceSystem).Get(ctx, consts.SecretName, metav1.GetOptions{})
	if getErr != nil {
		logger.Errorf("get secret error: %s", getErr)
		return false, &getErr
	}
	caCert := secret.Data["caCert.pem"]
	if len(webhookConfig.Webhooks) == 0 ||
		&(webhookConfig.Webhooks[0].ClientConfig) == nil ||
		!bytes.Equal(webhookConfig.Webhooks[0].ClientConfig.CABundle, caCert) {
		logger.Info("update webhookConfig for CABundle")
		return true, nil
	}
	return false, nil
}

func createOrUpdateSecret(ctx context.Context, clientset kubernetes.Interface, data goalresolvers.CertificateData) *error {
	logger := log.MustGetLogger(ctx)

	secret, getErr := clientset.CoreV1().Secrets(metav1.NamespaceSystem).Get(ctx, consts.SecretName, metav1.GetOptions{})

	if k8serrors.IsNotFound(getErr) {
		logger.Infof("create secret %s", consts.SecretName)
		cerr := createTlsSecret(ctx, clientset, data)
		if cerr != nil {
			logger.Errorf("fail to create secret %s. error: %s", consts.SecretName, *cerr)
			return cerr
		}
		return nil
	}

	if getErr != nil {
		logger.Errorf("get secret %s failed. error: %s", consts.SecretName, getErr)
		return &getErr
	}

	// Label has been checked in the goal resolver
	cerr := updateTlsSecret(ctx, clientset, data, secret)
	if cerr != nil {
		logger.Errorf("fail to update secret %s. error: %s", consts.SecretName, *cerr)
		return cerr
	}
	return nil
}

func createOrUpdateWebhook(ctx context.Context, clientset kubernetes.Interface, isKubeSystemNamespaceBlocked bool) *error {
	logger := log.MustGetLogger(ctx)
	secret, err := clientset.CoreV1().Secrets(metav1.NamespaceSystem).Get(ctx, consts.SecretName, metav1.GetOptions{})
	if err != nil {
		logger.Infof("fail to get secret %s. error: %s", consts.SecretName, err)
		return &err
	}

	client := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations()
	webhook, getErr := client.Get(ctx, consts.WebhookConfigName, metav1.GetOptions{})

	if k8serrors.IsNotFound(getErr) {
		logger.Infof("mutating webhook configuration %s doesn't exist", consts.WebhookConfigName)
		cerr := createMutatingWebhookConfig(ctx, clientset, secret.Data["caCert.pem"], isKubeSystemNamespaceBlocked)
		if cerr != nil {
			logger.Errorf("Create mutating webhook configuration failed. error: %s", *cerr)
			return cerr
		}
		logger.Info(ctx, "Create mutating webhook configuration succeed.")
		return nil
	}

	if getErr != nil {
		logger.Errorf("get mutating webhook configuration error: %s", getErr)
		return &getErr
	}

	if v, exist := webhook.ObjectMeta.Labels[consts.ManagedLabelKey]; !exist || v != consts.ManagedLabelValue {
		logger.Warningf("found mutating webhook configuration %s not managed by AKS", consts.WebhookConfigName)
		return nil
	}

	logger.Infof("mutating webhook configuration %s is managed by AKS", consts.WebhookConfigName)
	shouldUpdate, cerr := shouldUpdateWebhook(ctx, webhook, isKubeSystemNamespaceBlocked, clientset)
	if cerr != nil {
		return cerr
	}
	if shouldUpdate {
		cerr = updateMutatingWebhookConfig(ctx, clientset, isKubeSystemNamespaceBlocked, secret.Data["caCert.pem"])
		if cerr != nil {
			logger.Errorf("Update mutating webhook configuration failed. error: %s", *cerr)
			return cerr
		}
		logger.Info(ctx, "Update mutating webhook configuration succeed.")
	}
	return nil
}

func cleanupSecretAndWebhook(ctx context.Context, clientset kubernetes.Interface) *error {
	logger := log.MustGetLogger(ctx)

	deleteErr := clientset.CoreV1().Secrets(metav1.NamespaceSystem).Delete(ctx, consts.SecretName, metav1.DeleteOptions{})
	if deleteErr != nil {
		logger.Errorf("failed to cleanup secret %s. error: %s", consts.SecretName, deleteErr)
		return &deleteErr
	}
	logger.Infof("cleanup secret %s succeed.", consts.SecretName)

	client := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations()
	deleteErr = client.Delete(ctx, consts.WebhookConfigName, metav1.DeleteOptions{})
	if deleteErr != nil {
		logger.Errorf("failed to cleanup mutating webhook configuration %s. error: %s", consts.WebhookConfigName, deleteErr)
		return &deleteErr
	}
	logger.Infof("cleanup webhook %s succeed.", consts.WebhookConfigName)

	return nil
}

func createTlsSecret(ctx context.Context, clientset kubernetes.Interface, data goalresolvers.CertificateData) *error {
	logger := log.MustGetLogger(ctx)
	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      consts.SecretName,
			Namespace: metav1.NamespaceSystem,
			Labels: map[string]string{
				consts.ManagedLabelKey: consts.ManagedLabelValue,
			},
		},
		Data: map[string][]byte{
			"caCert.pem":     data.CaCertPem,
			"caKey.pem":      data.CaKeyPem,
			"serverCert.pem": data.ServerCertPem,
			"serverKey.pem":  data.ServerKeyPem,
		},
		Type: "Opaque",
	}

	_, createErr := clientset.CoreV1().Secrets(metav1.NamespaceSystem).Create(ctx, secret, metav1.CreateOptions{})
	if createErr != nil {
		logger.Errorf("create secret %s failed. error: %s", consts.SecretName, createErr)
		return &createErr
	}
	logger.Infof("secret %s created.", consts.SecretName)
	return nil
}

func updateTlsSecret(ctx context.Context, clientset kubernetes.Interface, data goalresolvers.CertificateData, secret *corev1.Secret) *error {
	logger := log.MustGetLogger(ctx)
	secret.Data["caCert.pem"] = data.CaCertPem
	secret.Data["caKey.pem"] = data.CaKeyPem
	secret.Data["serverCert.pem"] = data.ServerCertPem
	secret.Data["serverKey.pem"] = data.ServerKeyPem

	_, updateErr := clientset.CoreV1().Secrets(metav1.NamespaceSystem).Update(ctx, secret, metav1.UpdateOptions{})
	if updateErr != nil {
		logger.Errorf("update secret %s failed. error: %s", consts.SecretName, updateErr)
		return &updateErr
	}
	logger.Infof("secret %s updated.", consts.SecretName)
	return nil
}

func createMutatingWebhookConfig(ctx context.Context, clientset kubernetes.Interface, caCert []byte, isKubeSystemNamespaceBlocked bool) *error {
	logger := log.MustGetLogger(ctx)
	client := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations()
	registerClientConfig := admissionregistration.WebhookClientConfig{
		Service: &admissionregistration.ServiceReference{
			Name:      consts.ServiceName,
			Namespace: metav1.NamespaceSystem,
		},
		CABundle: caCert,
	}
	sideEffects := admissionregistration.SideEffectClassNone
	failurePolicy := admissionregistration.Ignore
	var labels map[string]string
	if !isKubeSystemNamespaceBlocked {
		logger.Info(ctx, "kube-system is unblocked.")
		labels = map[string]string{
			consts.ManagedLabelKey:                consts.ManagedLabelValue,
			consts.AdmissionEnforcerDisabledLabel: consts.AdmissionEnforcerDisabledValue,
		}
	} else {
		logger.Info(ctx, "kube-system is blocked.")
		labels = map[string]string{
			consts.ManagedLabelKey: consts.ManagedLabelValue,
		}
	}
	webhookConfig := &admissionregistration.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:   consts.WebhookConfigName,
			Labels: labels,
		},
		Webhooks: []admissionregistration.MutatingWebhook{
			{
				Name:                    "vpa.k8s.io",
				AdmissionReviewVersions: []string{"v1"},
				Rules: []admissionregistration.RuleWithOperations{
					{
						Operations: []admissionregistration.OperationType{admissionregistration.Create},
						Rule: admissionregistration.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods"},
						},
					},
					{
						Operations: []admissionregistration.OperationType{admissionregistration.Create, admissionregistration.Update},
						Rule: admissionregistration.Rule{
							APIGroups:   []string{"autoscaling.k8s.io"},
							APIVersions: []string{"*"},
							Resources:   []string{"verticalpodautoscalers"},
						},
					},
				},
				FailurePolicy:  &failurePolicy,
				ClientConfig:   registerClientConfig,
				SideEffects:    &sideEffects,
				TimeoutSeconds: &webhookTimeOutSeconds,
			},
		},
	}

	_, createErr := client.Create(ctx, webhookConfig, metav1.CreateOptions{})
	if createErr != nil {
		logger.Errorf("create mutating webhook configuration %s failed. error: %s", consts.WebhookConfigName, createErr)
		return &createErr

	}
	logger.Infof("mutating webhook configuration %s created.", consts.WebhookConfigName)
	return nil

}

func updateMutatingWebhookConfig(ctx context.Context, clientset kubernetes.Interface, isKubeSystemNamespaceBlocked bool, data []byte) *error {
	logger := log.MustGetLogger(ctx)
	client := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations()
	webhook, getErr := client.Get(ctx, consts.WebhookConfigName, metav1.GetOptions{})
	if getErr != nil {
		logger.Infof("fail to get mutating webhook config %s. error: %s", consts.WebhookConfigName, getErr)
		return &getErr
	}
	if !isKubeSystemNamespaceBlocked {
		logger.Info(ctx, "update label since kube-system is unblocked.")
		webhook.Labels[consts.AdmissionEnforcerDisabledLabel] = consts.AdmissionEnforcerDisabledValue
		webhook.Webhooks[0].NamespaceSelector = &metav1.LabelSelector{}
	} else {
		logger.Info(ctx, "update label since kube-system is blocked.")
		delete(webhook.Labels, consts.AdmissionEnforcerDisabledLabel)
	}
	if data != nil {
		webhook.Webhooks[0].ClientConfig.CABundle = data
	}
	_, updateErr := client.Update(ctx, webhook, metav1.UpdateOptions{})
	if updateErr != nil {
		logger.Infof("fail to update mutating webhook config %s. error: %s", consts.WebhookConfigName, getErr)
		return &updateErr
	}
	return nil
}

type webhookTlsManagerReconciler struct {
	webhookTlsManagerGoalResolver goalresolvers.WebhookTlsManagerGoalResolverInterface
	kubeClient                    kubernetes.Interface
}

func NewWebhookTlsManagerReconciler(webhookTlsManagerGoalResolver goalresolvers.WebhookTlsManagerGoalResolverInterface, kubeClient kubernetes.Interface) Reconciler {
	return &webhookTlsManagerReconciler{
		webhookTlsManagerGoalResolver: webhookTlsManagerGoalResolver,
		kubeClient:                    kubeClient,
	}
}

func (r *webhookTlsManagerReconciler) reconcileOnce(ctx context.Context) *error {
	logger := log.MustGetLogger(ctx)

	goal, cerr := r.webhookTlsManagerGoalResolver.Resolve(ctx)
	if cerr != nil {
		logger.Errorf("Resolve webhook goal failed. error: %s", *cerr)
		return cerr
	}

	if !goal.IsWebhookTlsManagerEnabled {
		cerr = cleanupSecretAndWebhook(ctx, r.kubeClient)
		if cerr != nil {
			logger.Errorf("cleanupSecretAndWebhook error: %s", *cerr)
			return cerr
		}
		logger.Info(ctx, "WebhookTlsManager is disabled. cleanup succeed.")
		return nil
	}

	// Rotate certificates.
	if goal.CertData != nil {
		metrics.RotateCertificateMetric.Set(1)
		cerr = createOrUpdateSecret(ctx, r.kubeClient, *goal.CertData)
		if cerr != nil {
			logger.Errorf("createOrUpdateSecret failed. error: %s", *cerr)
			return cerr
		}
	} else {
		metrics.RotateCertificateMetric.Set(0)
	}

	cerr = createOrUpdateWebhook(ctx, r.kubeClient, goal.IsKubeSystemNamespaceBlocked)
	if cerr != nil {
		logger.Errorf("createOrUpdateWebhook failed. error: %s", *cerr)
		return cerr
	}

	return nil
}

func (r *webhookTlsManagerReconciler) Reconcile(ctx context.Context) *error {
	logger := log.MustGetLogger(ctx)
	logger.Info(ctx, "Start reconciling webhook.")
	currentTime := time.Now()
	var cerr *error

	for i := 0; i < retryCount; i++ {
		if time.Since(currentTime) > retryTimeout {
			err := errors.New("reconcileOnce timeout")
			logger.Errorf("reconcileOnce timeout.")
			return &err
		}
		cerr = r.reconcileOnce(ctx)
		if cerr == nil {
			logger.Info(ctx, "Reconcile webhook succeed.")
			return nil
		}
		logger.Errorf("reconcileOnce failed. error: %s", *cerr)
		time.Sleep(retryInterval)
	}
	logger.Error("Reconcile webhook succeed.")
	return cerr
}
