package goalresolvers

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/webhook-tls-manager/config"
	"github.com/Azure/webhook-tls-manager/consts"
	"github.com/Azure/webhook-tls-manager/toolkit/certificates"
	"github.com/Azure/webhook-tls-manager/toolkit/log"
	"github.com/Azure/webhook-tls-manager/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

var _ = Describe("shouldRotateCert", func() {
	var (
		fakeClientset *fake.Clientset
		ctx           = log.WithLogger(context.Background(), log.NewLogger(context.Background(), 3))
	)

	BeforeEach(func() {
		fakeClientset = fake.NewSimpleClientset()
		config.NewConfig()
	})

	It("cert secret doesn't exist", func() {
		resolver := NewWebhookTlsManagerGoalResolver(ctx, fakeClientset, false, true).(*webhookTlsManagerGoalResolver)
		res, err := resolver.shouldRotateCert(ctx)
		Expect(err).To(BeNil())
		Expect(res).To(BeTrue())
	})

	It("get secret error", func() {
		fakeClientset.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, fmt.Errorf("get secrets error")
		})
		resolver := NewWebhookTlsManagerGoalResolver(ctx, fakeClientset, false, true).(*webhookTlsManagerGoalResolver)
		_, err := resolver.shouldRotateCert(ctx)
		Expect(err).NotTo(BeNil())
	})

	It("cert expired", func() {
		expiredCert, _ := certificates.GetPEMCertificateString(time.Now().Add(time.Hour * 24 * 15))
		secret := generateSecret(expiredCert, config.AppConfig.Namespace)
		fakeClientset = fake.NewSimpleClientset(secret)
		resolver := NewWebhookTlsManagerGoalResolver(ctx, fakeClientset, false, true).(*webhookTlsManagerGoalResolver)
		res, err := resolver.shouldRotateCert(ctx)
		Expect(err).To(BeNil())
		Expect(res).To(BeTrue())
	})

	It("cert unexpired", func() {
		cert, _ := certificates.GetPEMCertificateString(time.Now().Add(time.Hour * 24 * 60))
		secret := generateSecret(cert, config.AppConfig.Namespace)
		fakeClientset = fake.NewSimpleClientset(secret)
		resolver := NewWebhookTlsManagerGoalResolver(ctx, fakeClientset, false, true).(*webhookTlsManagerGoalResolver)
		res, err := resolver.shouldRotateCert(ctx)
		Expect(err).To(BeNil())
		Expect(res).To(BeFalse())
	})

	It("secret is not managed by aks", func() {
		secret := &corev1.Secret{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Secret",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      utils.SecretName(),
				Namespace: config.AppConfig.Namespace,
			},
			Data: map[string][]byte{},
			Type: "Opaque",
		}
		fakeClientset = fake.NewSimpleClientset(secret)
		resolver := NewWebhookTlsManagerGoalResolver(ctx, fakeClientset, false, true).(*webhookTlsManagerGoalResolver)
		res, err := resolver.shouldRotateCert(ctx)
		Expect(err).To(BeNil())
		Expect(res).To(BeFalse())
	})
})

var _ = Describe("generateCertificates", func() {

	var (
		ctx           context.Context
		logger        *logrus.Entry
		fakeClientset *fake.Clientset
	)

	BeforeEach(func() {
		logger = log.NewLogger(context.Background(), 3)
		ctx = log.WithLogger(context.Background(), logger)
		fakeClientset = fake.NewSimpleClientset()
		config.NewConfig()
	})

	It("succeed", func() {
		g := NewWebhookTlsManagerGoalResolver(ctx, fakeClientset, false, true).(*webhookTlsManagerGoalResolver)
		data, err := g.generateCertificates(ctx)
		Expect(err).To(BeNil())
		Expect(data.ServerCertPem).NotTo(BeNil())
		Expect(data.ServerKeyPem).NotTo(BeNil())
		Expect(data.CaCertPem).NotTo(BeNil())
		Expect(data.CaKeyPem).NotTo(BeNil())
	})
})

var _ = Describe("webhook tls manager goal resolver", func() {

	var (
		ctx           context.Context
		logger        *logrus.Entry
		fakeClientset *fake.Clientset
	)

	BeforeEach(func() {
		logger = log.NewLogger(context.Background(), 3)
		ctx = log.WithLogger(context.Background(), logger)
		fakeClientset = fake.NewSimpleClientset()
		config.NewConfig()
	})

	It("resolve fails: shouldRotateCert error", func() {
		fakeClientset = fake.NewSimpleClientset()
		fakeClientset.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, fmt.Errorf("get secrets error")
		})
		resolver := NewWebhookTlsManagerGoalResolver(ctx, fakeClientset, false, true).(*webhookTlsManagerGoalResolver)
		_, cerr := resolver.Resolve(ctx)
		Expect(cerr).NotTo(BeNil())
	})

	It("resolve succeed: don't rotate cert", func() {
		cert, _ := certificates.GetPEMCertificateString(time.Now().Add(time.Hour * 24 * 60))
		secret := generateSecret(cert, config.AppConfig.Namespace)
		fakeClientset = fake.NewSimpleClientset(secret)
		resolver := NewWebhookTlsManagerGoalResolver(ctx, fakeClientset, false, true)
		goal, cerr := resolver.Resolve(ctx)
		Expect(cerr).To(BeNil())
		Expect(goal.CertData).To(BeNil())
	})

	It("resolve succeed: new cert", func() {
		fakeClientset = fake.NewSimpleClientset()
		resolver := NewWebhookTlsManagerGoalResolver(ctx, fakeClientset, false, true)
		goal, cerr := resolver.Resolve(ctx)
		Expect(cerr).To(BeNil())
		Expect(goal.CertData).NotTo(BeNil())
	})
})

func generateSecret(cert string, namespace string) *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      utils.SecretName(),
			Namespace: namespace,
			Labels: map[string]string{
				consts.ManagedLabelKey: consts.ManagedLabelValue,
			},
		},
		Data: map[string][]byte{
			"serverCert.pem": []byte((cert)),
		},
		Type: "Opaque",
	}
}
