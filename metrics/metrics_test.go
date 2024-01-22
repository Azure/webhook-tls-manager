package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetrics(t *testing.T) {
	metricName := "vpa_webhook_generation_rotate_certificate_result"
	mf, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	metric := getMetrics(mf, metricName)
	require.NotNil(t, metric)
	assert.Equal(t, float64(0), metric.GetMetric()[0].GetGauge().GetValue())

	RotateCertificateMetric.Set(1)
	mf, err = prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	metric = getMetrics(mf, metricName)
	require.NotNil(t, metric)
	assert.Equal(t, float64(1), metric.GetMetric()[0].GetGauge().GetValue())
}

func getMetrics(gather []*dto.MetricFamily, metricName string) *dto.MetricFamily {
	for _, s := range gather {
		if s.GetName() == metricName {
			return s
		}
	}
	return nil
}
