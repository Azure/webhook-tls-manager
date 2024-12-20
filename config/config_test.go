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

}
