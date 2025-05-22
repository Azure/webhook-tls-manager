package config

import (
	"testing"
)

func TestConfig(t *testing.T) {
	t.Run("NewConfig", func(t *testing.T) {
		NewConfig()
	})

	t.Run("UpdateConfig", func(t *testing.T) {
		UpdateConfig("webhook-tls-manager", 1, 1, "kube-system")
		if AppConfig.ObjectName != "webhook-tls-manager" {
			t.Errorf("expected webhook-tls-manager, got %s", AppConfig.ObjectName)
		}
		if AppConfig.CaValidityYears != 1 {
			t.Errorf("expected 1, got %d", AppConfig.CaValidityYears)
		}
		if AppConfig.ServerValidityYears != 1 {
			t.Errorf("expected 1, got %d", AppConfig.ServerValidityYears)
		}
		if AppConfig.Namespace != "kube-system" {
			t.Errorf("expected kube-system, got %s", AppConfig.Namespace)
		}
	})

	t.Run("SecretName", func(t *testing.T) {
		expected := "webhook-tls-manager-tls-certs"
		if SecretName() != expected {
			t.Errorf("expected %s, got %s", expected, SecretName())
		}
	})

	t.Run("WebhookConfigName", func(t *testing.T) {
		expected := "webhook-tls-manager-webhook-config"
		if WebhookConfigName() != expected {
			t.Errorf("expected %s, got %s", expected, WebhookConfigName())
		}
	})

	t.Run("ServiceName", func(t *testing.T) {
		expected := "webhook-tls-manager-webhook"
		if ServiceName() != expected {
			t.Errorf("expected %s, got %s", expected, ServiceName())
		}
	})

	t.Run("CACertificateCommonName", func(t *testing.T) {
		expected := "webhook-tls-manager_webhook_ca"
		if CACertificateCommonName() != expected {
			t.Errorf("expected %s, got %s", expected, CACertificateCommonName())
		}
	})

	t.Run("ServerCertificateCommonName", func(t *testing.T) {
		expected := "webhook-tls-manager-webhook.kube-system.svc"
		if ServerCertificateCommonName() != expected {
			t.Errorf("expected %s, got %s", expected, ServerCertificateCommonName())
		}
	})

	t.Run("MetricsPrefix", func(t *testing.T) {
		expected := "webhook-tls-manager_metrics"
		if MetricsPrefix() != expected {
			t.Errorf("expected %s, got %s", expected, MetricsPrefix())
		}
	})

}
