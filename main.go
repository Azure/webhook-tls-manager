package main

import (
	"context"
	"flag"
	"net/http"
	"os"

	"github.com/Azure/webhook-tls-manager/config"
	"github.com/Azure/webhook-tls-manager/consts"
	"github.com/Azure/webhook-tls-manager/goalresolvers"
	"github.com/Azure/webhook-tls-manager/metrics"
	"github.com/Azure/webhook-tls-manager/reconcilers"
	"github.com/Azure/webhook-tls-manager/toolkit/log"
	"github.com/Azure/webhook-tls-manager/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	getKubeClientFunc          = utils.GetKubeClient
	webhookTlsManagerEnabled   = flag.Bool("webhook-tls-manager-enabled", true, "if set to false, it will cleanup webhook tls manager secrets and webhook.")
	kubeSystemNamespaceBlocked = flag.Bool("kube-system-namespace-blocked", false, "if set to false, all of the objects under kube-system namespace will be applied by the webhook.")
	namespace                  = flag.String("namespace", "", "the namespace of the object to be reconciled")
	addr                       = ":8943"
	objectName                 = flag.String("webhook-tls-manager-managed-object-name", "", "the name of the object to be reconciled")
	caValidityYears            = flag.Int("ca-validity-years", 0, "the validity of the CA certificate in years")
	serverValidityYears        = flag.Int("server-validity-years", 0, "the validity of the server certificate in years")
	logLevel                   = flag.Int("log-level", 3, "log level")
)

func main() {

	flag.Parse()
	config.NewConfig()
	config.UpdateConfig(*objectName, *caValidityYears, *serverValidityYears)
	logger := log.NewLogger(context.Background(), *logLevel)
	ctx := log.WithLogger(context.TODO(), logger)
	var label prometheus.Labels
	if *webhookTlsManagerEnabled {
		logger.Info("AKS Webhook TLS Manager Reconciliation Job")
		label = prometheus.Labels{"job": consts.ReconciliationJob}
	} else {
		logger.Info("AKS Webhook TLS Manager Cleanup Job")
		label = prometheus.Labels{"job": consts.CleanupJob}
	}
	kubeClient := getKubeClientFunc()
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		if err := http.ListenAndServe(addr, nil); err != nil {
			logger.Errorf("failed to start http server: %s", err)
		}
	}()

	webhookGoalResolver := goalresolvers.NewWebhookTlsManagerGoalResolver(ctx, kubeClient, *kubeSystemNamespaceBlocked, *webhookTlsManagerEnabled, *namespace)
	webhookTlsManagerReconciler := reconcilers.NewWebhookTlsManagerReconciler(webhookGoalResolver, kubeClient, *namespace)

	cerr := webhookTlsManagerReconciler.Reconcile(ctx)
	if cerr != nil {
		logger.Errorf("WebhookTlsManagerReconciler failed. error: %s", *cerr)
		metrics.ResultMetric.With(label).Set(1)
		os.Exit(1)
	}
	metrics.ResultMetric.With(label).Set(0)
}
