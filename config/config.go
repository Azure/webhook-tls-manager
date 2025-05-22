package config

import (
	"github.com/Azure/webhook-tls-manager/toolkit/certificates"
)

type Config struct {
	ObjectName          string
	CaValidityYears     int
	ServerValidityYears int
	Namespace           string
}

var AppConfig Config

func NewConfig() {
	AppConfig = Config{
		ObjectName:          "webhook-tls-manager",
		CaValidityYears:     certificates.CaValidityYears,
		ServerValidityYears: certificates.ServerValidityYears,
		Namespace:           "kube-system",
	}
}

func UpdateConfig(objectName string, caValidityYears int, serverValidityYears int, namespace string) {
	if objectName != "" {
		AppConfig.ObjectName = objectName
	}
	if caValidityYears != 0 {
		AppConfig.CaValidityYears = caValidityYears
	}
	if serverValidityYears != 0 {
		AppConfig.ServerValidityYears = serverValidityYears
	}
	if namespace != "" {
		AppConfig.Namespace = namespace
	}
}

func SecretName() string {
	return AppConfig.ObjectName + "-tls-certs"
}

func WebhookConfigName() string {
	return AppConfig.ObjectName + "-webhook-config"
}

func ServiceName() string {
	return AppConfig.ObjectName + "-webhook"
}

func CACertificateCommonName() string {
	return AppConfig.ObjectName + "_webhook_ca"
}

func ServerCertificateCommonName() string {
	return AppConfig.ObjectName + "-webhook." + AppConfig.Namespace + ".svc"
}

func MetricsPrefix() string {
	return AppConfig.ObjectName + "_metrics"
}
