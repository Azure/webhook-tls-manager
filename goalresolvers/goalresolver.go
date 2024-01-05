package goalresolvers

import (
	
)

type CertificateData struct {
	CaCertPem     []byte
	CaKeyPem      []byte
	ServerCertPem []byte
	ServerKeyPem  []byte
}

type OverlayVpaWebhookGoal struct {
	CertData                     *CertificateData
	IsKubeSystemNamespaceBlocked bool
	IsVPAEnabled                 bool
}

type overlayVpaWebhookGoalResolver struct {
	certOperator                 certoperator.Interface
	kubeClient                   kubernetes.Interface
	isKubeSystemNamespaceBlocked bool
	IsVPAEnabled                 bool
}

func