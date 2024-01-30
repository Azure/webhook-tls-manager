package utils

import (
	"github.com/Azure/webhook-tls-manager/config"
	"k8s.io/autoscaler/vertical-pod-autoscaler/common"
	"k8s.io/client-go/kubernetes"
)

const (
	kubeconfig   = ""
	kubeApiQps   = 5.0
	kubeApiBurst = 10.0
)

func GetKubeClient() kubernetes.Interface {
	config := common.CreateKubeConfigOrDie(kubeconfig, float32(kubeApiQps), int(kubeApiBurst))
	kubeClient := kubernetes.NewForConfigOrDie(config)
	var clientInterface kubernetes.Interface = kubeClient
	return clientInterface
}

func SecretName() string {
	return config.AppConfig.ObjectName + "-tls-certs"
}

func WebhookConfigName() string {
	return config.AppConfig.ObjectName + "-webhook-config"
}

func ServiceName() string {
	return config.AppConfig.ObjectName + "-webhook"
}

func CACertificateCommonName() string {
	return config.AppConfig.ObjectName + "_webhook_ca"
}

func ServerCertificateCommonName() string {
	return config.AppConfig.ObjectName + "-webhook.kube-system.svc"
}

func MetricsPrefix() string {
	return config.AppConfig.ObjectName + "_metrics"
}
