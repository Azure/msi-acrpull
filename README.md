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
helm install acrpull ./config/helm
```

This will install the custom resource definitions as well as the controllers, in whichever namespace you prefer. A new
version of Kubernetes (1.30+) is required, as we utilize `ValidatingAdmissionPolicies`.

# How to use

Using `acrpullbindings.acrpull.microsoft.com/v1beta2`, a `.dockercfg` `Secret` may be created and assigned as a pull
secret to a `ServiceAccount` of your choosing. The `acrpull` controller can use user-assigned managed identity credentials
either if they are assigned to the VMSS on which the `acrpull` controller is running, or, preferably, through workload
identity federation to service accounts in the namespace. New deployments of `acrpull` should use the latter approach;
the former remains as a back-stop for users who have not yet migrated.

### Filtering bindings with label selectors

When running the controller you can scope which `AcrPullBinding` objects are reconciled by passing the
`--label-selector` flag. The value uses the exact [Kubernetes label selector syntax](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors),
so multiple requirements and operators such as `!=`, `in`, `notin`, and `exists` are supported.

For example, to only reconcile bindings in non-production environments for a particular tier you could run the
controller with:

```shell
/manager \
  --label-selector "environment!=prod,tier in (frontend,backend)"
```

This selector will match any `AcrPullBinding` that has `tier` set to either `frontend` or `backend` while also ensuring
that `environment` is not equal to `prod`. Leaving the flag unset causes the controller to reconcile every
`AcrPullBinding` in the cluster.

## A note on pull secrets

When `Pod`s are created to fulfill `Deployment`s, `DaemonSet`s, _etc_, `pod.spec.imagePullSecrets` is defaulted from
the pull secrets attached to the `ServiceAccount` referenced in `pod.spec.serviceAccount`, if present. This is a one-time
action done during admission and the field is immutable afterword. This means that `ACRPullBinding` is, by default, racy.
A valid series of events looks like this:

1. a user creates an `ACRPullBinding` for a particular service account
2. the `acrpull` controller creates the pull secret
3. a user creates a `Deployment` referencing the service account
4. the `Deployment` controller creates a `Pod`
5. admission control defaults the list of `imagePullSecrets` on the `Pod` to the current list on the `ServiceAccount`, `[]`
6. the `acrpull` controller attaches the pull secret to a service account
7. the `Pod` is in a terminal state, as it references no pull secrets and will never be able to start

This unfortunate series of events is by design and cannot be mitigated if the user expects to confer image pull credentials
by attaching them to a service account. The only mitigation is to list the pull credential explicitly on the `PodSpec` and
omit associating a `Pod` with a `ServiceAccount`, unless the association is necessary for some other reason.

In order to make this easy, `acrpull` will mint pull credentials with names known _a priori_. v1beta1 `ACRPullBindings` will
mint `Secrets` named `<binding-name>-msi-acrpull-secret`, as long as the binding name is short enough that the overall name
is a valid `Secret` name. v1beta2 `ACRPullBindings` will mint `Secrets` named `acr-pull-<binding-name>`, with the same requirement
for binding names.

The suggested workflow is, therefore, to assume the name of the pull `Secret` that `acrpull` will generate and list it
explicitly in the `PodSpec` of any associated `Pods`. If the secret does not yet exist when the `Pod` is scheduled, the
`kubelet` will re-try the image pull later.

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

// ACR Image Puller Role needed by non-ABAC registries. For info on ABAC vs non-ABAC registries, please see https://aka.ms/acr/auth/abac for the correct built-in role to assign for pulling images.
// https://learn.microsoft.com/en-us/azure/container-registry/container-registry-rbac-built-in-roles-overview?tabs=registries-configured-with-rbac-registry-abac-repository-permissions#recommended-built-in-roles-by-scenario
// https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/containers#acrpull
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

// ACR Container Registry Repository Reader role needed by ABAC-enabled registries. For info on ABAC vs non-ABAC registries, please see https://aka.ms/acr/auth/abac for the correct built-in role to assign for pulling images.
// https://learn.microsoft.com/en-us/azure/container-registry/container-registry-rbac-built-in-roles-overview?tabs=registries-configured-with-rbac-registry-abac-repository-permissions#recommended-built-in-roles-by-scenario
// https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/containers#container-registry-repository-reader
var acrContainerRegistryRepositoryReaderId = 'b93aa761-3e63-49ed-ac28-beffa264f7ac'
resource pullerAbacRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(uniqueIdentifier, resourceGroup().id, pullerIdentity.id, acrContainerRegistryRepositoryReaderId)
  scope: registry
  properties: {
    roleDefinitionId: resourceId('Microsoft.Authorization/roleDefinitions', acrContainerRegistryRepositoryReaderId)
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
