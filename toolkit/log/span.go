package log

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	otelTrace "go.opentelemetry.io/otel/trace"
)

type otelSpan struct {
	span otelTrace.Span
}

type spanKeyType struct{}

var spanKey = spanKeyType{}

// SetSpanInContext stores a Span in context
func SetSpanInContext(ctx context.Context, span Span) context.Context {
	return context.WithValue(ctx, spanKey, span)
}

func (s *otelSpan) getAttribute(k string, v interface{}) attribute.KeyValue {
	switch val := v.(type) {
	case string:
		return attribute.String(k, val)
	case int:
		return attribute.Int64(k, int64(val))
	case int64:
		return attribute.Int64(k, val)
	case float64:
		return attribute.Float64(k, val)
	case bool:
		return attribute.Bool(k, val)
	default:
		return attribute.String(k, fmt.Sprintf("%v", val))
	}
}

// Inject implements Span.
func (s *otelSpan) Inject(ctx context.Context) TraceMap {
	propogator := propagation.TraceContext{}
	carrier := TraceMap{}
	propogator.Inject(ctx, propagation.MapCarrier(carrier))
	return carrier
}

func (s *otelSpan) SetAttributes(attributes map[string]interface{}) {
	if !s.IsValid() {
		return
	}

	attrs := []attribute.KeyValue{}
	for k, v := range attributes {
		attrs = append(attrs, s.getAttribute(k, v))
	}
	s.span.SetAttributes(attrs...)
}

var _ Span = &otelSpan{}

func (s *otelSpan) GetSpanID() string {
	if !s.IsValid() {
		return ""
	}
	return s.span.SpanContext().SpanID().String()
}

func (s *otelSpan) GetTraceID() string {
	if !s.IsValid() {
		return ""
	}
	return s.span.SpanContext().TraceID().String()
}

func (s *otelSpan) End() {
	if !s.IsValid() {
		return
	}
	s.span.End()
}

func (s *otelSpan) SetStatus(err error) {
	if !s.IsValid() {
		return
	}

	if err != nil {
		s.span.SetStatus(codes.Error, err.Error())
	} else {
		s.span.SetStatus(codes.Ok, "success")
	}
}

func (s *otelSpan) IsValid() bool {
	return s != nil && s.span != nil && s.span.SpanContext().IsValid()
}

func (s *otelSpan) AnnotateSpan(name string, attributes map[string]interface{}) {
	if !s.IsValid() {
		return
	}

	attrs := []attribute.KeyValue{}
	for k, v := range attributes {
		attrs = append(attrs, s.getAttribute(k, v))
	}
	s.span.AddEvent(name, otelTrace.WithAttributes(attrs...))
}
