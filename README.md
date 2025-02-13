# ACR Pull

The `acrpull` controller enables deployments in an AKS cluster to use any user assigned managed identity to pull images
from Azure Container Registry either by accessing credentials assigned to the VMSS of the AKS worker nodes, or by
leveraging federated workload credentials. With this, each application can use its own identity to pull container
images.

# Install

We provide a Helm chart for installation at `config/helm`. We have not yet published this to any registry, and we are
not attempting to handle every possible configuration case with the chart. Please try the chart and give any feedback.

With the repository cloned down, install with:

```shell
helm install ./config/helm
```

This will install the custom resource definitions as well as the controllers, in whichever namespace you prefer. A new
version of Kubernetes (1.30+) is required, as we utilize `ValidatingAdmissionPolicies`.

# How to use

Using `acrpullbindings.acrpull.microsoft.com/v1beta2`, a `.dockercfg` `Secret` may be created and assigned as a pull
secret to a `ServiceAccount` of your choosing. The `acrpull` controller can use user-assigned managed identity credentials
either if they are assigned to the VMSS on which the `acrpull` controller is running, or, preferably, through workload
identity federation to service accounts in the namespace. New deployments of `acrpull` should use the latter approach;
the former remains as a back-stop for users who have not yet migrated.

## Federated Workload Identities

Once an AKS cluster is deployed, create some identity with permissions to interact with an ACR instance:

```bicep
resource registry 'Microsoft.ContainerRegistry/registries@2023-01-01-preview' = {
  name: uniqueString(uniqueIdentifier, 'acr')
  location: location
  sku: {
    name: 'Basic'
  }
}

resource pullerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: guid(uniqueIdentifier, registry.id, 'puller')
  location: location
}

// ACR Image Puller Role:
// https://learn.microsoft.com/en-us/azure/container-registry/container-registry-roles?tabs=azure-cli#pull-image
// https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#containers
var acrImagePullerId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
resource pullerRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(uniqueIdentifier, resourceGroup().id, pullerIdentity.id, acrImagePullerId)
  scope: registry
  properties: {
    roleDefinitionId: resourceId('Microsoft.Authorization/roleDefinitions', acrImagePullerId)
    principalType: 'ServicePrincipal'
    principalId: pullerIdentity.properties.principalId
  }
}
```

Then, federate it with the AKS cluster, choosing an audience - this *must* match the audience provided to the controller
with `--service-account-token-audience`. The Helm chart does not (yet) expose this, the default value is `api://AzureCRTokenExchange`.
This value is intentionally chosen to be unique, as we can then restrict our controller's ability to mint tokens, scoping
behavior for this audience only and increasing security. The federated identity credential might look like this, with
appropriate values for the service account's namespace and name:

```bicep
resource federatedCredential 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = {
  name: guid(aks.id, pullerIdentity.id)
  parent: pullerIdentity
  properties: {
    audiences: [
      'api://AzureCRTokenExchange'
    ]
    issuer: aks.properties.oidcIssuerProfile.issuerURL
    subject: 'system:serviceaccount:NAMESPACE:SERVICE-ACCOUNT-NAME'
  }
}
```

Finally, create the `ACRPullBinding` to project the managed identity's credentials into a service account's pull secrets:

```yaml
apiVersion: acrpull.microsoft.com/v1beta2
kind: AcrPullBinding
metadata:
  name: pull-binding
  namespace: application
spec:
  acr:
    environment: PublicCloud
    scope: repository:<repository-name>:pull
    server: <acr-host>.azurecr.io
  auth:
    workloadIdentity:
      serviceAccountRef: <sa-name-with-fic>
  serviceAccountName: <sa-name-to-project-into>
```

## Managed Service Identities

> NOTE: the following steps are not recommended, but remain here for posterity. Prefer to use federated workload identity.

Once an AKS cluster is stood up, a user-assigned managed identity may be bound to the VMSS for the worker nodes using
some imperative logic and the `az` CLI. Refer to the end-to-end test's `Makefile` target for `_output/system-vmss-puller.json`
as an example.

Create an `ACRPullBinding` to project this credential:

```yaml
apiVersion: acrpull.microsoft.com/v1beta2
kind: AcrPullBinding
metadata:
  name: pull-binding
  namespace: application
spec:
  acr:
    environment: PublicCloud
    scope: repository:<repository-name>:pull
    server: <acr-host>.azurecr.io
  auth:
    managedIdentity:
      resourceID: /subscriptions/<uuid>/resourceGroups/<rg>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/<id>
  serviceAccountName: <sa-name-to-project-into>
```

## Migrating From v1beta1 to v1beta2

Users of the previous `v1beta1` API are strongly recommended to migrate to `v1beta2`. This release brings two breaking
changes:

1. a new Helm chart to facilitate deployment of the controller, CRDs, and VAP
2. ACR scopes are now required in pull bindings

We recommend the following steps to migrate:

1. Ensure at least v0.1.4 is running, if not, upgrade to this version and ensure it has processed every `ACRPullbinding`.
1. Deploy the CRDs from the current `acrpull` repository.
1. Fully remove the previous installation if `msi-acrpull` and deploy the new `acrpull` controller. This may mean that
   the `ACRPullBinding` API is unresponsive for a short period of time, but existing pull secrets will continue to function
   so no outage will occur.
1. Deploy the new `acrpull` controller and VAP.
1. Upgrade `ACRPullBinding` objects from `v1beta1` to `v1beta2` at your own pace.

### A note on upgrades

If v0.1.5 is installed before v0.1.4 has had time to run to completion, the validating admission policies will not allow
legacy credentials to be cleaned up. Please upgrade to v0.1.8 to unblock this flow, then follow steps starting from 2 above.

It is **NOT SUPPORTED** to upgrade from v0.1.3 to v0.1.9 or higher. This will break the existing pull bindings on the cluster.
Ensure that v0.1.4 or v0.1.8 are installed in between v0.1.3 and anything v0.1.9 or higher for a successful upgrade.

### A note on scopes

The container registry spec does not allow for blanket "pull everything in this registry" permissions in a scope, so a
scope must be provided for every registry that an `ACRPullBinding` is configured for. Scopes may be chained as a space-
delimited list.

# Contributing

This project welcomes contributions and suggestions. Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
