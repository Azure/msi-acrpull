
# MSI ACR Pull
MSI ACR Pull enables deployments in a Kubernetes cluster to use any user assigned managed identity to pull images from Azure Container Registry. With this, each application can use its own identity to pull container images.

# Install
Run following command to install latest build from main branch. It will install the needed custom resource definition `ACRPullBinding` and deploy msi-acrpull controllers in `msi-acrpull-system` namespace.

```bash
kubectl apply -f https://raw.githubusercontent.com/Azure/msi-acrpull/main/deploy/latest/crd.yaml -f https://raw.githubusercontent.com/Azure/msi-acrpull/main/deploy/latest/deploy.yaml
```

# How to use
> NOTE: following steps assumes you already have:
> 1) An Kubernetes cluster, and have user assigned managed identities on node pool VMSS.
> 1) An ACR, and the user assigned identity has [AcrPull](https://docs.microsoft.com/en-us/azure/container-registry/container-registry-roles#pull-image) role assigned on ACR.

Once msi-acrpull is installed to your cluster, all you need is to deploy a custom resource `AcrPullBinding` to the application namesapce to bind an user assigned identity to an ACR. Following sample specifies all pods using default service account in the namespace to use user managed identity `my-acr-puller` to pull image from `veryimportantcr.azurecr.io`.

```yaml
apiVersion: msi-acrpull.microsoft.com/v1beta1
kind: AcrPullBinding
metadata:
  name: acrpulltest
spec:
  acrServer: veryimportantcr.azurecr.io
  managedIdentityResourceID: /subscriptions/712288dc-f816-4242-b73f-a0a87265dcc8/resourceGroups/my-identities/providers/Microsoft.ManagedIdentity/userAssignedIdentities/my-acr-puller
```

Once the custom resource deployed, you can deploy your application to pull images from the ACR. No changes to the application deployment yaml is needed. 

> If the application pod uses a custom service account, then specify `serviceAccountName` property in AcrPullBinding spec.
## Default Values
If you use the same MSI and ACR endpoint for all your container, you can provide a default value to the controller.
To do so, set the environment variables on the `msi-acrpull-controller-manager` container :

3 default values can be set : 
- ACR_SERVER
- MANAGED_IDENTITY_RESOURCE_ID
- MANAGED_IDENTITY_CLIENT_ID


These environment variables are used if the `ACRPullBinding` crd does not set them.
Deployment spec example: 

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    control-plane: controller-manager
  name: msi-acrpull-controller-manager
  namespace: msi-acrpull-system
spec:
  replicas: 2
  selector:
    matchLabels:
      control-plane: controller-manager
  template:
    metadata:
      labels:
        control-plane: controller-manager
    spec:
      containers:
      - args:
        - --metrics-addr=127.0.0.1:8080
        - --enable-leader-election
        env:
        - name: "ACR_SERVER"
          value: "myacr.azurecr.io"
        - name: "MANAGED_IDENTITY_RESOURCE_ID"
          value: "<you managed identity resource id>"
        command:
        - /manager
        image: mcr.microsoft.com/aks/msi-acrpull:v0.1.0-alpha
        name: manager
        resources:
          limits:
            cpu: 100m
            memory: 100Mi
          requests:
            cpu: 100m
            memory: 20Mi
      - args:
        - --secure-listen-address=0.0.0.0:8443
        - --upstream=http://127.0.0.1:8080/
        - --logtostderr=true
        - --v=10
        image: gcr.io/kubebuilder/kube-rbac-proxy:v0.5.0
        name: kube-rbac-proxy
        ports:
        - containerPort: 8443
          name: https
      terminationGracePeriodSeconds: 10
```


# How it works
The architecture looks like below. As an user you will create a custom resource `ACRPullBinding`, which binds a managed identity (using client ID or resource ID) to an Azure container registry (using its FQDN). 

Internally, the `ACRPullBindingController` watches the `ACRPullBinding` resource, and for each of them, create a secret in the namespace. The secret content is a Docker image pull config, and the password is the ACR access token that the controller exchanged from ACR using managed identity. The secret will be refreshed 30min before it expire automatically. The controller will also associate the secret to the specified service account in namespace (by default, use the default service account). With this, any pods created in the namespace will automatically pull images from the ACR using the specified managed identity credential.

![Diagram](https://github.com/Azure/msi-acrpull/blob/main/docs/msi-acrpull-flow.png)

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
