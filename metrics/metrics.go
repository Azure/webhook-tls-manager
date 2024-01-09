package metrics

// import (
// 	"github.com/prometheus/client_golang/prometheus"

// 	"github.com/Azure/webhook-tls-manager/consts"
// )

// var (
// 	ResultMetric = prometheus.NewGaugeVec(
// 		prometheus.GaugeOpts{
// 			Subsystem: consts.MetricsPrefix,
// 			Name:      "webhook_job_succeed",
// 			Help:      "Result of webhook job, 1 is failed and 0 is successful",
// 		},
// 		[]string{"job"},
// 	)
// 	RotateCertificateMetric = prometheus.NewGauge(
// 		prometheus.GaugeOpts{
// 			Subsystem: consts.MetricsPrefix,
// 			Name:      "rotate_certificate_result",
// 			Help:      "Whether or not to rotate certificate, 0 is not rotate and 1 is rotate",
// 		},
// 	)
// )

// func init() {
// 	prometheus.MustRegister(RotateCertificateMetric)
// 	prometheus.MustRegister(ResultMetric)
// }
