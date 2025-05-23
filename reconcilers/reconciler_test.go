package reconcilers

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"
	admissionregistration "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/Azure/webhook-tls-manager/config"
	"github.com/Azure/webhook-tls-manager/consts"
	"github.com/Azure/webhook-tls-manager/goalresolvers"
	"github.com/Azure/webhook-tls-manager/goalresolvers/mock_goal_resolvers"
	"github.com/Azure/webhook-tls-manager/metrics"
	"github.com/Azure/webhook-tls-manager/toolkit/log"
)

const (
	caBundleKey   = "caCert.pem"
	caBundleValue = "different-from-secret"
)

var _ = Describe("currentWebhookConfigAndConfigmapDifferent", func() {
	var (
		ctx                        context.Context
		currentWebhookConfig       *admissionregistration.MutatingWebhookConfiguration
		webhookConfigFromConfigmap *admissionregistration.MutatingWebhookConfiguration
		currentMutatingWebhooks    []admissionregistration.MutatingWebhook
		mutatingWebhooks           []admissionregistration.MutatingWebhook
	)

	BeforeEach(func() {
		config.NewConfig()
		ctx = log.NewLogger(3).WithLogger(context.Background())
		currentMutatingWebhooks = []admissionregistration.MutatingWebhook{
			{
				Name: "vpa.k8s.io",
				ClientConfig: admissionregistration.WebhookClientConfig{
					Service: &admissionregistration.ServiceReference{
						Namespace: "kube-system",
						Name:      "vpa-admission-controller",
						Path:      nil,
					},
					URL:      nil,
					CABundle: []byte(caBundleValue),
				},
				Rules: []admissionregistration.RuleWithOperations{
					{
						Operations: []admissionregistration.OperationType{
							admissionregistration.Create,
						},
						Rule: admissionregistration.Rule{
							APIGroups:   []string{"autoscaling.k8s.io"},
							APIVersions: []string{"*"},
							Resources:   []string{"verticalpodautoscalers"},
							Scope:       nil,
						},
					},
				},
			},
		}
		mutatingWebhooks = []admissionregistration.MutatingWebhook{
			{
				Name: "vpa.k8s.io",
				ClientConfig: admissionregistration.WebhookClientConfig{
					Service: &admissionregistration.ServiceReference{
						Namespace: "kube-system",
						Name:      "vpa-admission-controller",
						Path:      nil,
					},
					URL:      nil,
					CABundle: []byte(caBundleValue),
				},
				Rules: []admissionregistration.RuleWithOperations{
					{
						Operations: []admissionregistration.OperationType{
							admissionregistration.Create,
							admissionregistration.Update,
						},
						Rule: admissionregistration.Rule{
							APIGroups:   []string{"autoscaling.k8s.io"},
							APIVersions: []string{"*"},
							Resources:   []string{"verticalpodautoscalers"},
							Scope:       nil,
						},
					},
				},
			},
		}
		config.NewConfig()
	})

	It("different label", func() {
		currentWebhookConfig = mutatingWebhookConfiguration(true)
		webhookConfigFromConfigmap = mutatingWebhookConfiguration(true)
		webhookConfigFromConfigmap.Labels = map[string]string{
			"test": "test",
		}
		res := currentWebhookConfigAndConfigmapDifferent(ctx, currentWebhookConfig, webhookConfigFromConfigmap)
		Expect(res).To(BeTrue())
	})

	It("different fields", func() {
		currentWebhookConfig = mutatingWebhookConfiguration(true)
		webhookConfigFromConfigmap = mutatingWebhookConfiguration(true)
		currentWebhookConfig.Webhooks = currentMutatingWebhooks
		webhookConfigFromConfigmap.Webhooks = mutatingWebhooks
		res := currentWebhookConfigAndConfigmapDifferent(ctx, currentWebhookConfig, webhookConfigFromConfigmap)
		Expect(res).To(BeTrue())
	})

	It("same", func() {
		currentWebhookConfig = mutatingWebhookConfiguration(true)
		webhookConfigFromConfigmap = mutatingWebhookConfiguration(true)
		res := currentWebhookConfigAndConfigmapDifferent(ctx, currentWebhookConfig, webhookConfigFromConfigmap)
		Expect(res).To(BeFalse())
	})

})

var _ = Describe("shouldUpdateWebhook", func() {

	var (
		ctx     context.Context
		webhook *admissionregistration.MutatingWebhookConfiguration
		client  *fake.Clientset
		s       *corev1.Secret
	)

	BeforeEach(func() {
		config.NewConfig()
		ctx = log.NewLogger(3).WithLogger(context.Background())
		s = secret(config.AppConfig.Namespace)
		client = fake.NewSimpleClientset(s, prepareCM(config.AppConfig.Namespace))
	})

	It("kube system is blocked and need to update webhook label", func() {
		webhook = mutatingWebhookConfiguration(false)
		webhook.Webhooks[0].ClientConfig.CABundle = s.Data[caBundleKey]
		res, err := shouldUpdateWebhook(ctx, webhook, true, client)
		Expect(err).To(BeNil())
		Expect(res).To(BeTrue())
	})

	It("kube system is unblocked and need to update webhook label", func() {
		webhook = mutatingWebhookConfiguration(true)
		webhook.Webhooks[0].ClientConfig.CABundle = s.Data[caBundleKey]
		res, err := shouldUpdateWebhook(ctx, webhook, false, client)
		Expect(err).To(BeNil())
		Expect(res).To(BeTrue())
	})

	It("need to update caBundle", func() {
		webhook = mutatingWebhookConfiguration(false)
		webhook.Webhooks[0].ClientConfig.CABundle = []byte(caBundleValue)
		res, err := shouldUpdateWebhook(ctx, webhook, false, client)
		Expect(err).To(BeNil())
		Expect(res).To(BeTrue())
	})
})

var _ = Describe("createOrUpdateSecret", func() {
	var (
		fakeClientset *fake.Clientset
		data          = goalresolvers.CertificateData{
			CaCertPem:     []byte("caCert"),
			CaKeyPem:      []byte("caKeyPem"),
			ServerCertPem: []byte("serverCertPem"),
			ServerKeyPem:  []byte("serverKeyPem"),
		}
		ctx = log.NewLogger(3).WithLogger(context.Background())
		s   *corev1.Secret
	)

	BeforeEach(func() {
		config.NewConfig()
		s = secret(config.AppConfig.Namespace)
		fakeClientset = fake.NewSimpleClientset(prepareCM(config.AppConfig.Namespace))
	})

	It("secret not exists and create secret error", func() {
		fakeClientset.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, fmt.Errorf("get secrets error")
		})

		cerr := createOrUpdateSecret(ctx, fakeClientset, data)
		Expect(cerr).NotTo(BeNil())
	})

	It("secret not exists and create secret succeed", func() {
		cerr := createOrUpdateSecret(ctx, fakeClientset, data)
		Expect(cerr).To(BeNil())
		secret, err := fakeClientset.CoreV1().Secrets(config.AppConfig.Namespace).Get(ctx, config.SecretName(), metav1.GetOptions{})
		Expect(err).To(BeNil())
		Expect(secret.Data["caCert.pem"]).To(BeEquivalentTo("caCert"))
	})

	It("get secret error", func() {
		fakeClientset = fake.NewSimpleClientset(s, prepareCM(config.AppConfig.Namespace))
		fakeClientset.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, fmt.Errorf("get secrets error")
		})

		cerr := createOrUpdateSecret(ctx, fakeClientset, data)
		Expect(cerr).NotTo(BeNil())
	})

	It("update secret error", func() {
		fakeClientset = fake.NewSimpleClientset(s, prepareCM(config.AppConfig.Namespace))
		fakeClientset.PrependReactor("update", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, fmt.Errorf("update secrets error")
		})

		cerr := createOrUpdateSecret(ctx, fakeClientset, data)
		Expect(cerr).NotTo(BeNil())
	})

	It("update secret succeed", func() {
		fakeClientset = fake.NewSimpleClientset(s, prepareCM(config.AppConfig.Namespace))
		cerr := createOrUpdateSecret(ctx, fakeClientset, data)
		Expect(cerr).To(BeNil())
		secret, err := fakeClientset.CoreV1().Secrets(config.AppConfig.Namespace).Get(ctx, config.SecretName(), metav1.GetOptions{})
		Expect(err).To(BeNil())
		Expect(secret.Data["caCert.pem"]).To(BeEquivalentTo("caCert"))
	})

})

var _ = Describe("createOrUpdateWebhook", func() {

	var (
		ctx    context.Context
		client *fake.Clientset
	)

	BeforeEach(func() {
		config.NewConfig()
		ctx = log.NewLogger(3).WithLogger(context.Background())
		client = fake.NewSimpleClientset(secret(config.AppConfig.Namespace), prepareCM(config.AppConfig.Namespace))
	})

	It("create webhook and get secret error", func() {
		client.PrependReactor("get", "secrets", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, nil, fmt.Errorf("error")
		})
		cerr := createOrUpdateWebhook(ctx, client, false)
		Expect(cerr).NotTo(BeNil())
	})

	It("create webhook error", func() {
		client.PrependReactor("create", "mutatingwebhookconfigurations", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, nil, fmt.Errorf("error")
		})
		cerr := createOrUpdateWebhook(ctx, client, false)
		Expect(cerr).NotTo(BeNil())
	})

	It("create webhook succeed", func() {
		cerr := createOrUpdateWebhook(ctx, client, false)
		Expect(cerr).To(BeNil())
		webhook, res := client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, config.WebhookConfigName(), metav1.GetOptions{})
		Expect(res).To(BeNil())
		Expect(webhook).NotTo(BeNil())
	})

	It("update webhook error", func() {
		client = fake.NewSimpleClientset(secret(config.AppConfig.Namespace), mutatingWebhookConfiguration(false), prepareCM(config.AppConfig.Namespace))
		client.PrependReactor("update", "mutatingwebhookconfigurations", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, nil, fmt.Errorf("error")
		})
		cerr := createOrUpdateWebhook(ctx, client, false)
		Expect(cerr).NotTo(BeNil())
	})

	It("update webhook succeed", func() {
		client = fake.NewSimpleClientset(mutatingWebhookConfiguration(true), secret(config.AppConfig.Namespace), prepareCM(config.AppConfig.Namespace))
		cerr := createOrUpdateWebhook(ctx, client, false)
		Expect(cerr).To(BeNil())
		webhook, res := client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, config.WebhookConfigName(), metav1.GetOptions{})
		Expect(res).To(BeNil())
		Expect(webhook).NotTo(BeNil())
		Expect(webhook.ObjectMeta.Labels[consts.AdmissionEnforcerDisabledLabel]).To(BeEquivalentTo(consts.AdmissionEnforcerDisabledValue))
	})

	It("webhook not managed by aks exists", func() {
		webhookConfig := &admissionregistration.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: config.WebhookConfigName(),
				Labels: map[string]string{
					consts.ManagedLabelKey: "non-aks",
				},
			},
		}
		client = fake.NewSimpleClientset(webhookConfig, secret(config.AppConfig.Namespace), prepareCM(config.AppConfig.Namespace))
		cerr := createOrUpdateWebhook(ctx, client, false)
		Expect(cerr).To(BeNil())
		webhook, res := client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, config.WebhookConfigName(), metav1.GetOptions{})
		Expect(res).To(BeNil())
		Expect(webhook).NotTo(BeNil())
		Expect(webhook.Labels[consts.ManagedLabelKey]).To(BeEquivalentTo("non-aks"))
	})

})

var _ = Describe("cleanupSecretAndWebhook", func() {
	var (
		ctx           context.Context
		fakeClientset *fake.Clientset
	)

	BeforeEach(func() {
		config.NewConfig()
		ctx = log.NewLogger(3).WithLogger(context.TODO())
		fakeClientset = fake.NewSimpleClientset(prepareCM(config.AppConfig.Namespace))
	})

	It("delete secret error", func() {
		fakeClientset = fake.NewSimpleClientset(mutatingWebhookConfiguration(false), prepareCM(config.AppConfig.Namespace))
		cerr := cleanupSecretAndWebhook(ctx, fakeClientset)
		Expect(cerr).Error()
	})

	It("delete webhook error", func() {
		fakeClientset = fake.NewSimpleClientset(secret(config.AppConfig.Namespace), prepareCM(config.AppConfig.Namespace))
		cerr := cleanupSecretAndWebhook(ctx, fakeClientset)
		_, err := fakeClientset.CoreV1().Secrets(config.AppConfig.Namespace).Get(ctx, config.SecretName(), metav1.GetOptions{})
		Expect(k8serrors.IsNotFound(err)).To(BeTrue())
		Expect(cerr).Error()
	})

	It("succeed", func() {
		fakeClientset = fake.NewSimpleClientset(secret(config.AppConfig.Namespace), mutatingWebhookConfiguration(false), prepareCM(config.AppConfig.Namespace))
		cerr := cleanupSecretAndWebhook(ctx, fakeClientset)
		Expect(cerr).To(BeNil())
	})
})

var _ = Describe("createTlsSecret", func() {
	var (
		fakeClientset *fake.Clientset
		data          = goalresolvers.CertificateData{
			CaCertPem:     []byte("caCert"),
			CaKeyPem:      []byte("caKeyPem"),
			ServerCertPem: []byte("serverCertPem"),
			ServerKeyPem:  []byte("serverKeyPem"),
		}
		ctx = log.NewLogger(3).WithLogger(context.TODO())
	)

	BeforeEach(func() {
		config.NewConfig()
		fakeClientset = fake.NewSimpleClientset(prepareCM(config.AppConfig.Namespace))
	})

	It("no secret exists", func() {
		cerr := createTlsSecret(ctx, fakeClientset, data)
		Expect(cerr).To(BeNil())
		secret, err := fakeClientset.CoreV1().Secrets(config.AppConfig.Namespace).Get(ctx, config.SecretName(), metav1.GetOptions{})
		Expect(err).To(BeNil())
		Expect(secret).NotTo(BeNil())
	})

	It("create error", func() {
		fakeClientset = fake.NewSimpleClientset(prepareCM(config.AppConfig.Namespace))
		fakeClientset.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, fmt.Errorf("create secrets error")
		})
		cerr := createTlsSecret(ctx, fakeClientset, data)
		Expect(cerr).NotTo(BeNil())
	})
})

var _ = Describe("updateTlsSecret", func() {
	var (
		fakeClientset *fake.Clientset
		data          = goalresolvers.CertificateData{
			CaCertPem:     []byte("caCert"),
			CaKeyPem:      []byte("caKeyPem"),
			ServerCertPem: []byte("serverCertPem"),
			ServerKeyPem:  []byte("serverKeyPem"),
		}
		ctx = log.NewLogger(3).WithLogger(context.TODO())
		s   *corev1.Secret
	)

	BeforeEach(func() {
		config.NewConfig()
		s = secret(config.AppConfig.Namespace)
		fakeClientset = fake.NewSimpleClientset(s, prepareCM(config.AppConfig.Namespace))
	})

	It("update secret error", func() {
		fakeClientset.PrependReactor("update", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, fmt.Errorf("update secrets error")
		})

		cerr := updateTlsSecret(ctx, fakeClientset, data, s)
		Expect(cerr).NotTo(BeNil())
	})

	It("update secret succeed", func() {
		cerr := updateTlsSecret(ctx, fakeClientset, data, s)
		Expect(cerr).To(BeNil())

		secret, err := fakeClientset.CoreV1().Secrets(config.AppConfig.Namespace).Get(ctx, config.SecretName(), metav1.GetOptions{})
		Expect(err).To(BeNil())
		Expect(secret.Data["caCert.pem"]).To(BeEquivalentTo("caCert"))
	})
})

var _ = Describe("getMutatingWebhookConfigFromConfigmap", func() {
	var (
		fakeClientset *fake.Clientset
		caCertPem     = []byte("caCert")
		ctx           = log.NewLogger(3).WithLogger(context.TODO())
	)

	BeforeEach(func() {
		config.NewConfig()
		fakeClientset = fake.NewSimpleClientset(prepareCM(config.AppConfig.Namespace))
	})

	It("success", func() {
		webhook, err := getMutatingWebhookConfigFromConfigmap(ctx, fakeClientset, caCertPem, true)
		Expect(err).To(BeNil())
		Expect(webhook.Webhooks[0].Name).To(Equal("vpa.k8s.io"))
	})

	It("get configmap error", func() {
		fakeClientset = fake.NewSimpleClientset()
		webhook, err := getMutatingWebhookConfigFromConfigmap(ctx, fakeClientset, caCertPem, true)
		Expect(err).NotTo(BeNil())
		Expect(webhook).To(BeNil())
	})

	It("get data error", func() {
		fakeClientset = fake.NewSimpleClientset(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: "webhook-tls-manager-webhook-config",
			},
		})
		webhook, err := getMutatingWebhookConfigFromConfigmap(ctx, fakeClientset, caCertPem, true)
		Expect(err).NotTo(BeNil())
		Expect(webhook).To(BeNil())
	})
})

var _ = Describe("createMutatingWebhookConfig test", func() {
	var (
		fakeClientset *fake.Clientset
		caCertPem     = []byte("caCert")
		ctx           = log.NewLogger(3).WithLogger(context.TODO())
	)

	BeforeEach(func() {
		config.NewConfig()
		fakeClientset = fake.NewSimpleClientset(prepareCM(config.AppConfig.Namespace))
	})

	It("success", func() {
		name := "webhook-tls-manager-webhook-config"
		cerr := createMutatingWebhookConfig(ctx, fakeClientset, caCertPem, true)
		Expect(cerr).To(BeNil())
		webhook, err := fakeClientset.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, name, metav1.GetOptions{})
		Expect(err).To(BeNil())
		Expect(webhook.Webhooks[0].Name).To(Equal("vpa.k8s.io"))

		_, keyExist := webhook.ObjectMeta.Labels[consts.AdmissionEnforcerDisabledLabel]
		Expect(keyExist).To(BeFalse())
		val, keyExist := webhook.ObjectMeta.Labels[consts.ManagedLabelKey]
		Expect(keyExist).To(BeTrue())
		Expect(val).To(BeEquivalentTo(consts.ManagedLabelValue))
	})

	It("mutatingWebhookConfig is empty", func() {
		cm := prepareCM(config.AppConfig.Namespace)
		cm.Data["mutatingWebhookConfig"] = ""
		fakeClientset = fake.NewSimpleClientset(cm)
		cerr := createMutatingWebhookConfig(ctx, fakeClientset, caCertPem, true)
		Expect(cerr).NotTo(BeNil())
	})

	It("getMutatingWebhookConfigFromConfigmap error", func() {
		fakeClientset = fake.NewSimpleClientset()
		cerr := createMutatingWebhookConfig(ctx, fakeClientset, caCertPem, true)
		Expect(cerr).NotTo(BeNil())
	})

	It("create error", func() {
		fakeClientset.PrependReactor("create", "mutatingwebhookconfigurations", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, fmt.Errorf("create webhook error")
		})
		cerr := createMutatingWebhookConfig(ctx, fakeClientset, caCertPem, true)
		Expect(cerr).NotTo(BeNil())
		webhook, err := fakeClientset.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, config.WebhookConfigName(), metav1.GetOptions{})
		Expect(err).NotTo(BeNil())
		Expect(webhook).To(BeNil())
	})

	It("unblock kube-system namespace", func() {
		cerr := createMutatingWebhookConfig(ctx, fakeClientset, caCertPem, false)
		Expect(cerr).To(BeNil())
		webhook, err := fakeClientset.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, config.WebhookConfigName(), metav1.GetOptions{})
		Expect(err).To(BeNil())

		_, keyExist := webhook.ObjectMeta.Labels[consts.AdmissionEnforcerDisabledLabel]
		Expect(keyExist).To(BeTrue())
	})
})

var _ = Describe("updateMutatingWebhookConfig test", func() {
	var (
		fakeClientset *fake.Clientset
		ctx           = log.NewLogger(3).WithLogger(context.TODO())
		webhook       *admissionregistration.MutatingWebhookConfiguration
	)

	BeforeEach(func() {
		config.NewConfig()
		webhook = mutatingWebhookConfiguration(true)
		fakeClientset = fake.NewSimpleClientset(webhook, prepareCM(config.AppConfig.Namespace))
	})

	It("get webhook error", func() {
		fakeClientset = fake.NewSimpleClientset(prepareCM(config.AppConfig.Namespace))
		cerr := updateMutatingWebhookConfig(ctx, fakeClientset, false, []byte{})
		Expect(cerr).NotTo(BeNil())
	})

	It("update webhook error", func() {
		fakeClientset.PrependReactor("update", "mutatingwebhookconfigurations", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, nil, fmt.Errorf("update webhook error")
		})
		cerr := updateMutatingWebhookConfig(ctx, fakeClientset, false, []byte{})
		Expect(cerr).NotTo(BeNil())
	})

	It("update webhook when kube-system is blocked", func() {
		webhook.Labels[consts.AdmissionEnforcerDisabledLabel] = "true"
		fakeClientset = fake.NewSimpleClientset(webhook, prepareCM(config.AppConfig.Namespace))
		cerr := updateMutatingWebhookConfig(ctx, fakeClientset, true, []byte{})
		Expect(cerr).To(BeNil())
		res, err := fakeClientset.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, config.WebhookConfigName(), metav1.GetOptions{})
		Expect(err).To(BeNil())
		_, keyExist := res.Labels[consts.AdmissionEnforcerDisabledLabel]
		Expect(keyExist).To(BeFalse())
		Expect(res.Webhooks[0].ClientConfig.CABundle).To(BeEmpty())
	})

	It("update webhook when kube-system is unblocked", func() {
		caCert := []byte("test")
		cerr := updateMutatingWebhookConfig(ctx, fakeClientset, false, caCert)
		Expect(cerr).To(BeNil())
		res, err := fakeClientset.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, config.WebhookConfigName(), metav1.GetOptions{})
		Expect(err).To(BeNil())
		Expect(res.Labels[consts.AdmissionEnforcerDisabledLabel]).To(BeEquivalentTo("true"))
		Expect(res.Webhooks[0].ClientConfig.CABundle).To(BeEquivalentTo(caCert))
	})
})

var _ = Describe("webhook tls manager reconciler reconcile", func() {
	var (
		ctx          context.Context
		client       *fake.Clientset
		mockctl      *gomock.Controller
		goalresolver *mock_goal_resolvers.MockWebhookTlsManagerGoalResolverInterface
		certData     goalresolvers.CertificateData
	)

	BeforeEach(func() {
		config.NewConfig()
		ctx = log.NewLogger(3).WithLogger(context.TODO())
		mockctl = gomock.NewController(GinkgoT())
		client = fake.NewSimpleClientset(prepareCM(config.AppConfig.Namespace))
		goalresolver = mock_goal_resolvers.NewMockWebhookTlsManagerGoalResolverInterface(mockctl)
		certData = goalresolvers.CertificateData{
			CaCertPem:     []byte("CaCertPem"),
			CaKeyPem:      []byte("CaKeyPem"),
			ServerCertPem: []byte("ServerCertPem"),
			ServerKeyPem:  []byte("ServerKeyPem"),
		}
	})

	It("goalresolver resolve fail", func() {
		rerr := errors.New("GenerateCertificates error")
		goalresolver.EXPECT().Resolve(ctx).Return(nil, &rerr).AnyTimes()

		reconciler := NewWebhookTlsManagerReconciler(goalresolver, client)
		err := reconciler.Reconcile(ctx)

		Expect(err).NotTo(BeNil())
	})

	It("reconcile fail: WebhookTlsManager disabled and cleanup error", func() {
		goal := goalresolvers.WebhookTlsManagerGoal{
			CertData:                     &certData,
			IsKubeSystemNamespaceBlocked: false,
			IsWebhookTlsManagerEnabled:   false,
		}
		goalresolver.EXPECT().Resolve(ctx).Return(&goal, nil).AnyTimes()

		reconciler := NewWebhookTlsManagerReconciler(goalresolver, client)
		cerr := reconciler.Reconcile(ctx)

		Expect(cerr).Error()
	})

	It("reconcile succeed: WebhookTlsManager disabled and cleanup succeed", func() {
		goal := goalresolvers.WebhookTlsManagerGoal{
			CertData:                     &certData,
			IsKubeSystemNamespaceBlocked: false,
			IsWebhookTlsManagerEnabled:   false,
		}
		goalresolver.EXPECT().Resolve(ctx).Return(&goal, nil).AnyTimes()

		client = fake.NewSimpleClientset(secret(config.AppConfig.Namespace), mutatingWebhookConfiguration(goal.IsKubeSystemNamespaceBlocked), prepareCM(config.AppConfig.Namespace))
		reconciler := NewWebhookTlsManagerReconciler(goalresolver, client)
		cerr := reconciler.Reconcile(ctx)

		Expect(cerr).To(BeNil())
		Expect(testutil.ToFloat64(metrics.RotateCertificateMetric)).To(BeEquivalentTo(0))
	})

	It("reconcile succeed: update webhook", func() {
		goal := goalresolvers.WebhookTlsManagerGoal{
			CertData:                     &certData,
			IsKubeSystemNamespaceBlocked: false,
			IsWebhookTlsManagerEnabled:   true,
		}
		goalresolver.EXPECT().Resolve(ctx).Return(&goal, nil)

		client = fake.NewSimpleClientset(secret(config.AppConfig.Namespace), mutatingWebhookConfiguration(goal.IsKubeSystemNamespaceBlocked), prepareCM(config.AppConfig.Namespace))
		reconciler := NewWebhookTlsManagerReconciler(goalresolver, client)
		cerr := reconciler.Reconcile(ctx)

		Expect(cerr).To(BeNil())
		Expect(testutil.ToFloat64(metrics.RotateCertificateMetric)).To(BeEquivalentTo(1))

		webhook, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, config.WebhookConfigName(), metav1.GetOptions{})
		Expect(webhook).NotTo(BeNil())
		Expect(webhook.Webhooks[0].ClientConfig.CABundle).To(BeEquivalentTo(goal.CertData.CaCertPem))
		Expect(err).To(BeNil())
		secret, err := client.CoreV1().Secrets(config.AppConfig.Namespace).Get(ctx, config.SecretName(), metav1.GetOptions{})
		Expect(secret).NotTo(BeNil())
		Expect(err).To(BeNil())
	})

	It("reconcile succeed", func() {
		goal := goalresolvers.WebhookTlsManagerGoal{
			CertData:                     &certData,
			IsKubeSystemNamespaceBlocked: false,
			IsWebhookTlsManagerEnabled:   true,
		}
		goalresolver.EXPECT().Resolve(ctx).Return(&goal, nil)

		reconciler := NewWebhookTlsManagerReconciler(goalresolver, client)
		cerr := reconciler.Reconcile(ctx)

		Expect(cerr).To(BeNil())

		webhook, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, config.WebhookConfigName(), metav1.GetOptions{})
		Expect(webhook).NotTo(BeNil())
		Expect(err).To(BeNil())
		secret, err := client.CoreV1().Secrets(config.AppConfig.Namespace).Get(ctx, config.SecretName(), metav1.GetOptions{})
		Expect(secret).NotTo(BeNil())
		Expect(err).To(BeNil())
	})

	It("rotate cert and create secret fail", func() {
		goal := goalresolvers.WebhookTlsManagerGoal{
			CertData:                     &certData,
			IsKubeSystemNamespaceBlocked: false,
			IsWebhookTlsManagerEnabled:   true,
		}
		goalresolver.EXPECT().Resolve(ctx).Return(&goal, nil).AnyTimes()
		client.PrependReactor("create", "secrets", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, nil, fmt.Errorf("error")
		})

		reconciler := NewWebhookTlsManagerReconciler(goalresolver, client)
		cerr := reconciler.Reconcile(ctx)

		Expect(cerr).NotTo(BeNil())
	})

	It("rotate cert and create webhook fail", func() {
		goal := goalresolvers.WebhookTlsManagerGoal{
			CertData:                     &certData,
			IsKubeSystemNamespaceBlocked: false,
			IsWebhookTlsManagerEnabled:   true,
		}
		goalresolver.EXPECT().Resolve(ctx).Return(&goal, nil).AnyTimes()
		client.PrependReactor("create", "mutatingwebhookconfigurations", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, nil, fmt.Errorf("error")
		})

		reconciler := NewWebhookTlsManagerReconciler(goalresolver, client)
		cerr := reconciler.Reconcile(ctx)

		Expect(cerr).NotTo(BeNil())
	})

	It("don't rotate cert and shouldCreateOrUpdateWebhook failed", func() {
		goal := goalresolvers.WebhookTlsManagerGoal{
			CertData:                     nil,
			IsKubeSystemNamespaceBlocked: false,
			IsWebhookTlsManagerEnabled:   true,
		}
		goalresolver.EXPECT().Resolve(ctx).Return(&goal, nil).AnyTimes()
		client = fake.NewSimpleClientset(secret(config.AppConfig.Namespace), prepareCM(config.AppConfig.Namespace))
		client.PrependReactor("get", "mutatingwebhookconfigurations", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, nil, fmt.Errorf("error")
		})

		reconciler := NewWebhookTlsManagerReconciler(goalresolver, client)
		cerr := reconciler.Reconcile(ctx)

		Expect(cerr).NotTo(BeNil())
	})

})

func mutatingWebhookConfiguration(systemNamespaceBlocked bool) *admissionregistration.MutatingWebhookConfiguration {
	var label map[string]string
	if systemNamespaceBlocked {
		label = map[string]string{
			consts.ManagedLabelKey: consts.ManagedLabelValue,
		}
	} else {
		label = map[string]string{
			consts.ManagedLabelKey:                consts.ManagedLabelValue,
			consts.AdmissionEnforcerDisabledLabel: "true",
		}
	}
	failurePolicy := admissionregistration.Fail
	matchPolicy := admissionregistration.Equivalent
	sideEffects := admissionregistration.SideEffectClassNone
	timeout := int32(3)
	port := int32(443)
	scope := admissionregistration.AllScopes
	return &admissionregistration.MutatingWebhookConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       "MutatingWebhookConfiguration",
			APIVersion: "admissionregistration.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   config.WebhookConfigName(),
			Labels: label,
		},
		Webhooks: []admissionregistration.MutatingWebhook{
			{
				Name:                    "vpa.k8s.io",
				AdmissionReviewVersions: []string{"v1"},
				ClientConfig: admissionregistration.WebhookClientConfig{
					Service: &admissionregistration.ServiceReference{
						Namespace: "kube-system",
						Name:      "webhook-tls-manager-webhook-config",
						Port:      &port,
						Path:      nil,
					},
				},
				FailurePolicy:  &failurePolicy,
				MatchPolicy:    &matchPolicy,
				SideEffects:    &sideEffects,
				TimeoutSeconds: &timeout,
				Rules: []admissionregistration.RuleWithOperations{
					{
						Operations: []admissionregistration.OperationType{
							admissionregistration.Create,
							admissionregistration.Update,
						},
						Rule: admissionregistration.Rule{
							APIGroups:   []string{"autoscaling.k8s.io"},
							APIVersions: []string{"*"},
							Resources:   []string{"verticalpodautoscalers"},
							Scope:       &scope,
						},
					},
					{
						Operations: []admissionregistration.OperationType{
							admissionregistration.Create,
						},
						Rule: admissionregistration.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods"},
							Scope:       &scope,
						},
					},
				},
			},
		},
	}
}

func secret(namespace string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-tls-manager-tls-certs",
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"caCert.pem":     []byte("testCaCert"),
			"caKey.pem":      []byte("testCaKey"),
			"serverCert.pem": []byte("testServerCert"),
			"serverKey.pem":  []byte("testServerKey"),
		},
	}
}

func prepareCM(namespace string) *corev1.ConfigMap {
	cmData := `
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: webhook-tls-manager-webhook-config
  labels:
    app.kubernetes.io/managed-by: aks
webhooks:
- admissionReviewVersions:
  - v1
  clientConfig:
    service:
      name: vpa-webhook
      namespace: vpa-recommender
      port: 443
  failurePolicy: Ignore
  matchPolicy: Equivalent
  name: vpa.k8s.io
  sideEffects: None
  timeoutSeconds: 3
  namespaceSelector:
    matchExpressions:
      - key: overlay-ccp-id
        operator: Exists
  objectSelector:
    matchLabels:
      auto-vpa: "enabled"
  rules:
  - apiGroups:
    - ""
    apiVersions:
    - v1
    operations:
    - CREATE
    resources:
    - pods
    scope: '*'
  - apiGroups:
    - autoscaling.k8s.io
    apiVersions:
    - '*'
    operations:
    - CREATE
    - UPDATE
    resources:
    - verticalpodautoscalers
    scope: '*'
`
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-tls-manager-webhook-config",
			Namespace: namespace,
		},
		Data: map[string]string{
			"mutatingWebhookConfig": cmData,
		},
	}
	return cm
}
