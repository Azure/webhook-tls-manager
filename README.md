# Webhook-tls-manager

Webhook-tls-manager is a Kubernetes component that manages webhooks and related certificates.

## Overview

Webhook-tls-manager simplifies the management of webhooks and certificates in Kubernetes. It provides functionality to **create webhook configurations and certificates, rotate expired certificates, reconcile webhook configurations and secrets, and clean up webhook configurations and certificates**.

## Examples

### Build image
```
export REGISTRY=alexhzf/webhook-tls-manager
export TAG=0.0.1
make docker-build
```

### Deploy charts through helm
Check out the `examples` folder for sample configurations and deployment files. The command uses helm to install a helm release. The configmap containing the mutating webhook configuration is in sample-cm.yaml. The `vpa-cert-webhook-check job` will create a secret with the certificate named as `vpa-tls-certs` and MutatingWebhookConfiguration `vpa-webhook-config`.

```
helm package examples/vpa-helm-chart
helm install vpa vpa-helm-chart-0.1.1.tgz -n kube-system
```

### Remove the helm release
A job `vpa-cert-webhook-cleanup` will be created to remove the secret and webhook.
```
helm uninstall vpa -n kube-system
```

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
