package reconcilers

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"time"

	admissionregistration "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"

	"github.com/Azure/webhook-tls-manager/config"
	"github.com/Azure/webhook-tls-manager/consts"
	"github.com/Azure/webhook-tls-manager/goalresolvers"
	"github.com/Azure/webhook-tls-manager/metrics"
	"github.com/Azure/webhook-tls-manager/toolkit/log"
	"github.com/Azure/webhook-tls-manager/utils"
)

const (
	retryCount    = 10
	retryInterval = 5 * time.Second
	retryTimeout  = 15 * time.Second
)

func currentWebhookConfigAndConfigmapDifferent(ctx context.Context, currentWebhookConfig *admissionregistration.MutatingWebhookConfiguration,
	// If the mutating webhook configuration has multiple webhooks, the result of this function is not accurate.
	// Because the reflect.DeepEqual function is impacted by the order of array elements.
	webhookConfigFromConfig *admissionregistration.MutatingWebhookConfiguration) bool {
	logger := log.MustGetLogger(ctx)
	if !reflect.DeepEqual(currentWebhookConfig.ObjectMeta.Labels, webhookConfigFromConfig.ObjectMeta.Labels) {
		logger.Info(ctx, "currentWebhookConfig.ObjectMeta different from webhookConfigFromConfig.ObjectMeta.Labels")
		logger.Debugf(ctx, "currentWebhookConfig.ObjectMeta.Labels: %v", currentWebhookConfig.ObjectMeta.Labels)
		logger.Debugf(ctx, "webhookConfigFromConfig.ObjectMeta.Labels: %v", webhookConfigFromConfig.ObjectMeta.Labels)
		return true
	}
	if !reflect.DeepEqual(currentWebhookConfig.Webhooks[0].ClientConfig.Service, webhookConfigFromConfig.Webhooks[0].ClientConfig.Service) ||
		!reflect.DeepEqual(currentWebhookConfig.Webhooks[0].Name, webhookConfigFromConfig.Webhooks[0].Name) ||
		!reflect.DeepEqual(currentWebhookConfig.Webhooks[0].NamespaceSelector, webhookConfigFromConfig.Webhooks[0].NamespaceSelector) ||
		!reflect.DeepEqual(currentWebhookConfig.Webhooks[0].ObjectSelector, webhookConfigFromConfig.Webhooks[0].ObjectSelector) ||
		!reflect.DeepEqual(currentWebhookConfig.Webhooks[0].Rules, webhookConfigFromConfig.Webhooks[0].Rules) {
		logger.Info(ctx, "currentWebhookConfig.Webhooks[0] different from webhookConfigFromConfig.Webhooks[0]")
		logger.Debugf(ctx, "currentWebhookConfig.Webhooks[0]: %v", currentWebhookConfig.Webhooks[0])
		logger.Debugf(ctx, "webhookConfigFromConfig.Webhooks[0]: %v", webhookConfigFromConfig.Webhooks[0])
		return true
	}

	return false
}

func shouldUpdateWebhook(ctx context.Context, webhookConfig *admissionregistration.MutatingWebhookConfiguration,
	isKubeSystemNamespaceBlocked bool, clientset kubernetes.Interface) (bool, *error) {
	logger := log.MustGetLogger(ctx)

	admissionEnforcerDisabled, labelExist := webhookConfig.Labels[consts.AdmissionEnforcerDisabledLabel]
	//If the value of admissionEnforcerDisabled is false, the kube-system namespace is blocked.
	if isKubeSystemNamespaceBlocked {
		logger.Info(ctx, "kube-system should be blocked")
		if labelExist && admissionEnforcerDisabled == consts.AdmissionEnforcerDisabledValue {
			return true, nil
		}
	} else {
		logger.Info(ctx, "kube-system should be unblocked")
		if !labelExist || admissionEnforcerDisabled != consts.AdmissionEnforcerDisabledValue {
			logger.Info(ctx, "update webhookConfig for label")
			return true, nil
		}
	}

	secret, getErr := clientset.CoreV1().Secrets(config.AppConfig.Namespace).Get(ctx, utils.SecretName(), metav1.GetOptions{})
	if getErr != nil {
		logger.Errorf(ctx, "get secret error: %s", getErr)
		return false, &getErr
	}
	caCert := secret.Data["caCert.pem"]
	if len(webhookConfig.Webhooks) == 0 ||
		!bytes.Equal(webhookConfig.Webhooks[0].ClientConfig.CABundle, caCert) {
		logger.Info(ctx, "update webhookConfig for CABundle")
		logger.Debugf(ctx, "webhookConfig.Webhooks[0].ClientConfig.CABundle: %x", webhookConfig.Webhooks[0].ClientConfig.CABundle)
		logger.Debugf(ctx, "caCert: %x", caCert)
		return true, nil
	}
	webhookConfigFromConfig, err := getMutatingWebhookConfigFromConfigmap(ctx, clientset, caCert, isKubeSystemNamespaceBlocked)
	if err != nil {
		logger.Errorf(ctx, "get webhookConfig from configmap error: %s", *err)
		return false, err
	}

	if currentWebhookConfigAndConfigmapDifferent(ctx, webhookConfig, webhookConfigFromConfig) {
		logger.Info(ctx, "update webhookConfig for webhookConfigFromConfig")
		return true, nil
	}

	return false, nil
}

func createOrUpdateSecret(ctx context.Context, clientset kubernetes.Interface, data goalresolvers.CertificateData) *error {
	logger := log.MustGetLogger(ctx)

	secret, getErr := clientset.CoreV1().Secrets(config.AppConfig.Namespace).Get(ctx, utils.SecretName(), metav1.GetOptions{})

	if k8serrors.IsNotFound(getErr) {
		logger.Infof(ctx, "create secret %s", utils.SecretName())
		cerr := createTlsSecret(ctx, clientset, data)
		if cerr != nil {
			logger.Errorf(ctx, "fail to create secret %s. error: %s", utils.SecretName(), *cerr)
			return cerr
		}
		return nil
	}

	if getErr != nil {
		logger.Errorf(ctx, "get secret %s failed. error: %s", utils.SecretName(), getErr)
		return &getErr
	}

	// Label has been checked in the goal resolver
	cerr := updateTlsSecret(ctx, clientset, data, secret)
	if cerr != nil {
		logger.Errorf(ctx, "fail to update secret %s. error: %s", utils.SecretName(), *cerr)
		return cerr
	}
	return nil
}

func createOrUpdateWebhook(ctx context.Context, clientset kubernetes.Interface, isKubeSystemNamespaceBlocked bool) *error {
	logger := log.MustGetLogger(ctx)
	secret, err := clientset.CoreV1().Secrets(config.AppConfig.Namespace).Get(ctx, utils.SecretName(), metav1.GetOptions{})
	if err != nil {
		logger.Infof(ctx, "fail to get secret %s. error: %s", utils.SecretName(), err)
		return &err
	}

	client := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations()
	webhook, getErr := client.Get(ctx, utils.WebhookConfigName(), metav1.GetOptions{})

	if k8serrors.IsNotFound(getErr) {
		logger.Infof(ctx, "mutating webhook configuration %s doesn't exist", utils.WebhookConfigName())
		cerr := createMutatingWebhookConfig(ctx, clientset, secret.Data["caCert.pem"], isKubeSystemNamespaceBlocked)
		if cerr != nil {
			logger.Errorf(ctx, "Create mutating webhook configuration failed. error: %s", *cerr)
			return cerr
		}
		logger.Info(ctx, "Create mutating webhook configuration succeed.")
		return nil
	}

	if getErr != nil {
		logger.Errorf(ctx, "get mutating webhook configuration error: %s", getErr)
		return &getErr
	}

	if v, exist := webhook.ObjectMeta.Labels[consts.ManagedLabelKey]; !exist || v != consts.ManagedLabelValue {
		logger.Warningf(ctx, "found mutating webhook configuration %s not managed by AKS", utils.WebhookConfigName())
		return nil
	}

	logger.Infof(ctx, "mutating webhook configuration %s is managed by AKS", utils.WebhookConfigName())
	shouldUpdate, cerr := shouldUpdateWebhook(ctx, webhook, isKubeSystemNamespaceBlocked, clientset)
	if cerr != nil {
		return cerr
	}
	if shouldUpdate {
		cerr = updateMutatingWebhookConfig(ctx, clientset, isKubeSystemNamespaceBlocked, secret.Data["caCert.pem"])
		if cerr != nil {
			logger.Errorf(ctx, "Update mutating webhook configuration failed. error: %s", *cerr)
			return cerr
		}
		logger.Info(ctx, "Update mutating webhook configuration succeed.")
	}
	return nil
}

func cleanupSecretAndWebhook(ctx context.Context, clientset kubernetes.Interface) *error {
	logger := log.MustGetLogger(ctx)

	deleteErr := clientset.CoreV1().Secrets(config.AppConfig.Namespace).Delete(ctx, utils.SecretName(), metav1.DeleteOptions{})
	if deleteErr != nil {
		logger.Errorf(ctx, "failed to cleanup secret %s. error: %s", utils.SecretName(), deleteErr)
		return &deleteErr
	}
	logger.Infof(ctx, "cleanup secret %s succeed.", utils.SecretName())

	client := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations()
	deleteErr = client.Delete(ctx, utils.WebhookConfigName(), metav1.DeleteOptions{})
	if deleteErr != nil {
		logger.Errorf(ctx, "failed to cleanup mutating webhook configuration %s. error: %s", utils.WebhookConfigName(), deleteErr)
		return &deleteErr
	}
	logger.Infof(ctx, "cleanup webhook %s succeed.", utils.WebhookConfigName())

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
			Name:      utils.SecretName(),
			Namespace: config.AppConfig.Namespace,
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

	_, createErr := clientset.CoreV1().Secrets(config.AppConfig.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	if createErr != nil {
		logger.Errorf(ctx, "create secret %s failed. error: %s", utils.SecretName(), createErr)
		return &createErr
	}
	logger.Infof(ctx, "secret %s created.", utils.SecretName())
	return nil
}

func updateTlsSecret(ctx context.Context, clientset kubernetes.Interface, data goalresolvers.CertificateData, secret *corev1.Secret) *error {
	logger := log.MustGetLogger(ctx)
	secret.Data["caCert.pem"] = data.CaCertPem
	secret.Data["caKey.pem"] = data.CaKeyPem
	secret.Data["serverCert.pem"] = data.ServerCertPem
	secret.Data["serverKey.pem"] = data.ServerKeyPem

	_, updateErr := clientset.CoreV1().Secrets(config.AppConfig.Namespace).Update(ctx, secret, metav1.UpdateOptions{})
	if updateErr != nil {
		logger.Errorf(ctx, "update secret %s failed. error: %s", utils.SecretName(), updateErr)
		return &updateErr
	}
	logger.Infof(ctx, "secret %s updated.", utils.SecretName())
	return nil
}

func getMutatingWebhookConfigFromConfigmap(ctx context.Context, clientset kubernetes.Interface, caCert []byte, isKubeSystemNamespaceBlocked bool) (*admissionregistration.MutatingWebhookConfiguration, *error) {
	logger := log.MustGetLogger(ctx)
	name := config.AppConfig.ObjectName + "-webhook-config"
	cm, err := clientset.CoreV1().ConfigMaps(config.AppConfig.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		logger.Errorf(ctx, "get webhook-config configmap failed. error: %s", err)
		return nil, &err
	}
	logger.Infof(ctx, "get webhook-config configmap succeed.")
	logger.Debugf(ctx, "configmap: %v", cm)

	mutatingWebhookConfigJson := cm.Data["mutatingWebhookConfig"]
	if mutatingWebhookConfigJson == "" {
		logger.Errorf(ctx, "mutatingWebhookConfig is empty")
		err = errors.New("mutatingWebhookConfig is empty")
		return nil, &err
	}
	logger.Infof(ctx, "get mutatingWebhookConfig succeed. mutatingWebhookConfig: %s", mutatingWebhookConfigJson)
	logger.Debugf(ctx, "mutatingWebhookConfig: %s", mutatingWebhookConfigJson)
	var mutatingWebhookConfig admissionregistration.MutatingWebhookConfiguration
	err = yaml.NewYAMLOrJSONDecoder(strings.NewReader(mutatingWebhookConfigJson), 1024).Decode(&mutatingWebhookConfig)
	if err != nil {
		logger.Errorf(ctx, "unmarshal mutatingWebhookConfig failed. error: %s", err)
		return nil, &err
	}
	logger.Infof(ctx, "unmarshal mutatingWebhookConfig succeed.")
	logger.Debugf(ctx, "mutatingWebhookConfig: %v", mutatingWebhookConfig)

	for i := range mutatingWebhookConfig.Webhooks {
		mutatingWebhookConfig.Webhooks[i].ClientConfig.CABundle = caCert
	}
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
	mutatingWebhookConfig.Labels = labels
	logger.Debugf(ctx, "mutatingWebhookConfig from configmap: %v", mutatingWebhookConfig)

	return &mutatingWebhookConfig, nil
}

func createMutatingWebhookConfig(ctx context.Context, clientset kubernetes.Interface, caCert []byte, isKubeSystemNamespaceBlocked bool) *error {
	logger := log.MustGetLogger(ctx)
	mutatingWebhookConfig, err := getMutatingWebhookConfigFromConfigmap(ctx, clientset, caCert, isKubeSystemNamespaceBlocked)
	if err != nil {
		logger.Errorf(ctx, "get mutating webhook config failed. error: %s", *err)
		return err
	}

	client := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations()

	_, createErr := client.Create(ctx, mutatingWebhookConfig, metav1.CreateOptions{})
	if createErr != nil {
		logger.Errorf(ctx, "create mutating webhook configuration %s failed. error: %s", utils.WebhookConfigName(), createErr)
		return &createErr

	}
	logger.Infof(ctx, "mutating webhook configuration %s created.", utils.WebhookConfigName())
	return nil

}

func updateMutatingWebhookConfig(ctx context.Context, clientset kubernetes.Interface, isKubeSystemNamespaceBlocked bool, data []byte) *error {
	logger := log.MustGetLogger(ctx)
	client := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations()
	webhook, getErr := client.Get(ctx, utils.WebhookConfigName(), metav1.GetOptions{})
	if getErr != nil {
		logger.Infof(ctx, "fail to get mutating webhook config %s. error: %s", utils.WebhookConfigName(), getErr)
		return &getErr
	}
	webhookFromCm, readErr := getMutatingWebhookConfigFromConfigmap(ctx, clientset, data, isKubeSystemNamespaceBlocked)
	if readErr != nil {
		logger.Infof(ctx, "fail to get mutating webhook config from configmap. error: %s", *readErr)
		return readErr
	}
	webhook.ObjectMeta.Labels = webhookFromCm.ObjectMeta.Labels
	webhook.Webhooks = webhookFromCm.Webhooks
	logger.Debugf(ctx, "webhook before update: %v", webhook)
	_, updateErr := client.Update(ctx, webhook, metav1.UpdateOptions{})
	if updateErr != nil {
		logger.Infof(ctx, "fail to update mutating webhook config %s. error: %s", utils.WebhookConfigName(), updateErr)
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
		logger.Errorf(ctx, "Resolve webhook goal failed. error: %s", *cerr)
		return cerr
	}

	if !goal.IsWebhookTlsManagerEnabled {
		cerr = cleanupSecretAndWebhook(ctx, r.kubeClient)
		if cerr != nil {
			logger.Errorf(ctx, "cleanupSecretAndWebhook error: %s", *cerr)
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
			logger.Errorf(ctx, "createOrUpdateSecret failed. error: %s", *cerr)
			return cerr
		}
	} else {
		metrics.RotateCertificateMetric.Set(0)
	}

	cerr = createOrUpdateWebhook(ctx, r.kubeClient, goal.IsKubeSystemNamespaceBlocked)
	if cerr != nil {
		logger.Errorf(ctx, "createOrUpdateWebhook failed. error: %s", *cerr)
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
			logger.Errorf(ctx, "reconcileOnce timeout.")
			return &err
		}
		cerr = r.reconcileOnce(ctx)
		if cerr == nil {
			logger.Info(ctx, "Reconcile webhook succeed.")
			return nil
		}
		logger.Warningf(ctx, "reconcileOnce failed. error: %s", *cerr)
		time.Sleep(retryInterval)
	}
	logger.Errorf(ctx, "Reconcile webhook failed. error: %s", *cerr)
	return cerr
}
