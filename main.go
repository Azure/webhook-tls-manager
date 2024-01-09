package webhooktlsmanager

import (
	"context"
	"flag"
	"os"

	"github.com/Azure/webhook-tls-manager/goalresolvers"
	"github.com/Azure/webhook-tls-manager/reconcilers"
	"github.com/Azure/webhook-tls-manager/toolkit/log"
	"github.com/Azure/webhook-tls-manager/utils"
)

var (
	getKubeClientFunc          = utils.GetKubeClient
	vpaEnabled                 = flag.Bool("vpa-enabled", true, "if set to false, it will cleanup overlay vpa secrets and webhook.")
	kubeSystemNamespaceBlocked = flag.Bool("kube-system-namespace-blocked", false, "if set to false, all of the objects under kube-system namespace will be able to use vpa.")
	addr                       = ":8943"
)

func main() {

	flag.Parse()
	logger := log.NewLogger(context.Background())
	ctx := log.WithLogger(context.TODO(), logger)
	// var label prometheus.Labels
	if *vpaEnabled {
		logger.Info("AKS Vertical Pod Autoscaler Webhook Reconciliation Job")
		// label = prometheus.Labels{"job": consts.ReconciliationJob}
	} else {
		logger.Info("AKS Vertical Pod Autoscaler Webhook Cleanup Job")
		// label = prometheus.Labels{"job": consts.CleanupJob}
	}
	kubeClient := getKubeClientFunc()
	// go func() {
	// 	glog.Fatal(httpxmetrics.ListenAndServe(addr, promhttp.Handler())) // +gocover:ignore:block - unreachable
	// }()

	webhookGoalResolver := goalresolvers.NewWebhookTlsManagerGoalResolver(ctx, kubeClient, *kubeSystemNamespaceBlocked, *vpaEnabled)
	webhookTlsManagerReconciler := reconcilers.NewWebhookTlsManagerReconciler(webhookGoalResolver, kubeClient)

	cerr := webhookTlsManagerReconciler.Reconcile(ctx)
	if cerr != nil {
		logger.Errorf("OverlayVpaCertReconciler failed. error: %s", *cerr)
		// metrics.ResultMetric.With(label).Set(1)
		os.Exit(1)
	}
	// metrics.ResultMetric.With(label).Set(0)
}
