
# MSI ACR Pull
MSI ACR Pull enables deployments in a Kubernetes cluster to use any user assigned managed identity to pull images from Azure container registry. With this, each application can use its own identity to pull container images.

# How it works
The architecture looks like below. As an user you will create a custom resource `ACRPullBinding`, which binds a managed identity (using client ID or resource ID) to an Azure container registry (using its FQDN). 

Internally, the `ACRPullBindingController` watches the `ACRPullBinding` resource, and for each of them, create a secret in the namespace. The secret content is a Docker image pull config, and the password is the ACR access token that the controller exchanged from ACR using managed identity. The secret will be refreshed 30min before it expire automatically. The controller will also associate the secret to the specified service account in namespace (by default, use the default service account). With this, any pods created in the namespace will automatically pull images from the ACR using the specified managed identity credential.

![Diagram](https://github.com/Azure/msi-acrpull/blob/master/docs/msi-acrpull-flow.png?raw=true)

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
