package consts

const (
	ManagedLabelValue              = "aks"
	ManagedLabelKey                = "app.kubernetes.io/managed-by"
	AdmissionEnforcerDisabledLabel = "admissions.enforcer/disabled"
	AdmissionEnforcerDisabledValue = "true"
	CleanupJob                     = "cleanup"
	ReconciliationJob              = "reconciliation"
)
