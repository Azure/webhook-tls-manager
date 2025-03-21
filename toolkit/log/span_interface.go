package log

//go:generate env GOFLAGS= GO111MODULE=on GOWORK=off mockgen -package=mock_log -destination=./mock_log/interface.go toolkit/log Span

import (
	"context"
)

type Span interface {
	GetSpanID() string
	GetTraceID() string
	SetStatus(err error)
	SetAttributes(attributes map[string]interface{})
	AnnotateSpan(name string, attributes map[string]interface{})
	Inject(ctx context.Context) TraceMap
	IsValid() bool
	End()
}

// traceMap is a carrier for trace context. It is used to propagate trace context
type TraceMap map[string]string
