package toolkit

import (
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
