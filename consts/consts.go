package consts

const (
	SecretName                     = "vpa-tls-certs"
	WebhookConfigName              = "vpa-webhook-config"
	ServiceName                    = "vpa-webhook"
	ManagedLabelValue              = "aks"
	ManagedLabelKey                = "app.kubernetes.io/managed-by"
	CommonName                     = "vpa_webhook_ca"
	ServerCommonName               = "vpa-webhook.kube-system.svc"
	LoggerSourceName               = "overlay-vpa-webhook-generation"
	AdmissionEnforcerDisabledLabel = "admissions.enforcer/disabled"
	AdmissionEnforcerDisabledValue = "true"
	CleanupJob                     = "cleanup"
	ReconciliationJob              = "reconciliation"
	MetricsPrefix                  = "vpa_webhook_generation"
)

type ActionStatus int

const (
	NoActionNeeded ActionStatus = iota
	CreateNeeded
	UpdateNeeded
)
