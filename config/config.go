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
