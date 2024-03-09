# Webhook-tls-manager

Webhook-tls-manager is a Kubernetes component that manages webhooks and related certificates.

## Overview

Webhook-tls-manager simplifies the management of webhooks and certificates in Kubernetes. It provides functionality to create webhook configurations and certificates, rotate expired certificates, reconcile webhook configurations and secrets, and clean up webhook configurations and certificates.

## Examples

Check out the `examples` folder for sample configurations and deployment files.

```
helm package examples/vpa-helm-chart
helm install vpa vpa-helm-chart-0.1.1.tgz -n kube-system
```

The above command uses helm to deploy the charts. The configmap containing the mutating webhook configuration is in sample-cm.yaml.

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
