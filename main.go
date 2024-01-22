package main

import (
	"context"
	"flag"
	"net/http"
	"os"

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
	kubeSystemNamespaceBlocked = flag.Bool("kube-system-namespace-blocked", false, "if set to false, all of the objects under kube-system namespace will be able to use vpa.")
	addr                       = ":8943"
)

func main() {

	flag.Parse()
	logger := log.NewLogger(context.Background())
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

	webhookGoalResolver := goalresolvers.NewWebhookTlsManagerGoalResolver(ctx, kubeClient, *kubeSystemNamespaceBlocked, *webhookTlsManagerEnabled)
	webhookTlsManagerReconciler := reconcilers.NewWebhookTlsManagerReconciler(webhookGoalResolver, kubeClient)

	cerr := webhookTlsManagerReconciler.Reconcile(ctx)
	if cerr != nil {
		logger.Errorf("WebhookTlsManagerReconciler failed. error: %s", *cerr)
		metrics.ResultMetric.With(label).Set(1)
		os.Exit(1)
	}
	metrics.ResultMetric.With(label).Set(0)
}
