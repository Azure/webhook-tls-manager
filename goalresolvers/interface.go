package goalresolvers

//go:generate sh -c "mockgen go.goms.io/aks/rp/ccp/overlay-vpa-webhook-generation/goalresolvers OverlayVpaWebhookGoalResolverInterface >./mock_$GOPACKAGE/goal_resolver_interface.go"

import (
	"context"
)

type WebhookTlsManagerGoalResolverInterface interface {
	Resolve(ctx context.Context) (goal *WebhookTlsManagerGoal, err *error)
}
