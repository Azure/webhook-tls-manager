package goalresolvers

//go:generate mockgen -destination=mock_goal_resolvers/goal_resolver.go -package=mock_goal_resolvers github.com/Azure/webhook-tls-manager/goalresolvers WebhookTlsManagerGoalResolverInterface

import (
	"context"
)

type WebhookTlsManagerGoalResolverInterface interface {
	Resolve(ctx context.Context) (goal *WebhookTlsManagerGoal, err *error)
}
