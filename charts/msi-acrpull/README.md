# msi-acrpull

[msi-acrpull](https://github.com/Azure/msi-acrpull) enables deployments in a Kubernetes cluster to use any user assigned managed identity to pull images from Azure Container Registry.

## TL;DR

```console
helm repo add msi-acrpull https://raw.githubusercontent.com/Azure/msi-acrpull/main/charts

# Helm 3
helm install msi-acrpull msi-acrpull/msi-acrpull

## Helm chart and msi-acrpull versions

| Helm Chart Version | MSI ACI Pull Version |
| ------------------ | ------------------------ |
| `v0.1.0-alpha`     | `v0.1.0-alpha`           |

## Introduction

A simple [helm](https://helm.sh/) chart for setting up the components needed to use [MSI ACR Pull](https://github.com/Azure/msi-acrpull) in Kubernetes.

This helm chart will deploy the following resources:
* ACRPullBinding `CustomResourceDefinition`
* MSI ACR Pull Controller `Deployment`
* AAD Pod Identity Binding `AAD Pod Identity Configuration`

#### Installing charts

To install the chart with the release name `my-release`:

```console
helm install my-release msi-acrpull/msi-acrpull
```

## Uninstalling the Chart

To uninstall/delete the last deployment:

```console
helm ls

# Helm 3
helm uninstall <ReleaseName>

# Helm 2
helm delete <ReleaseName> --purge
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

> The CRD created by the chart are not removed by default and should be manually cleaned up (if required)

```bash
kubectl delete crd amsi-acrpull.microsoft.com/v1beta1
```

## Configuration

The following tables list the configurable parameters of the msi-acrpull chart and their default values.

| Parameter                                 | Description                                                                                                                                                                                                                                                                                                                   | Default                                                        |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `nameOverride`                            | String to partially override charts.fullname template with a string (will prepend the release name)                                                                                                                                                                                                                | `""`      
| `fullnameOverride`                        | String to fully override charts.fullname template with a string                                                                                                                                                                                                                                                     | `""`                                                           |
| `imagePullSecrets`                        | One or more secrets to be used when pulling images                                                                                                                                                                                                                                                                            | `[]`                                                           |
| `msiacrpull.image.repository`                       | MSI ACR Pull Image Repository                                                                                                                                                                                                                                                                                                   | `mcr.microsoft.com/aks/msi-acrpull`
| `msiacrpull.image.pullPolicy`                       | MSI ACR Pull Image Pull Policy                                                                                                                                                                                                                                                                                                  | `IfNotPresent`
| `msiacrpull.image.tag`                       | MSI ACR Pull Image Tag                                                                                                                                                                                                                                                                                                   | `v0.1.0-alpha`
| `msiacrpull.securityContext`                       | MSI ACR Pull Container Security Context                                                                                                                                                                                                                                                                                                   | `{}`
| `msiacrpull.resources`                       | MSI ACR Pull Container Resources                                                                                                                                                                                                                                                                                                   | `see values.yaml`
| `kuberbacproxy.image.repository`                       | Kube RBAC Proxy Image Repository                                                                                                                                                                                                                                                                                                   | `gcr.io/kubebuilder/kube-rbac-proxy`
| `kuberbacproxy.image.pullPolicy`                       | Kube RBAC Proxy Image Pull Policy                                                                                                                                                                                                                                                                                                  | `IfNotPresent`
| `kuberbacproxy.image.tag`                       | Kube RBAC Proxy Image Tag                                                                                                                                                                                                                                                                                                   | `v0.5.0`
| `kuberbacproxy.securityContext`                       | Kube RBAC Proxy Container Security Context                                                                                                                                                                                                                                                                                                   | `{}`
| `kuberbacproxy.resources`                       | Kube RBAC Proxy Container Resources                                                                                                                                                                                                                                                                                                   | `{}`
| `serviceAccount.create`                       | Specifies whether a service account should be created                                                                                                                                                                                                                                                                                                  | `true`
| `serviceAccount.rbac`                       | Specifies whether the service account should be granted with necessary Kubernetes RBAC                                                                                                                                                                                                                                                                                                  | `true`
| `serviceAccount.name`                       | Override the service account name                                                                                                                                                                                                                                                                                                    | `""` 
| `podSecurityContext`                       | Pod Security Context                                                                                                                                                                                                                                                                                                  | `{}` 
| `podAnnotations`                       | Pod Annotations                                                                                                                                                                                                                                                                                                  | `{}`
| `nodeSelector`                       | Specifies node labels this pod should be deployed to                                                                                                                                                                                                                                                                                                 | `{}`  
| `affinity`                       | Pod Affinity                                                                                                                                                                                                                                                                                                 | `{}` 
| `tolerations`                       | Pod Tolerations                                                                                                                                                                                                                                                                                                | `[]`                                       

## Troubleshooting

If the helm chart is deleted and then reinstalled without manually deleting the crds, then you can get an error like -

```console
➜ helm install msi-acrpull msi-acrpull/msi-acrpull
Error: customresourcedefinitions.apiextensions.k8s.io "acrpullbindings.msi-acrpull.microsoft.com" already exists
```

In this case, since there is no update to the crd definition since it was last installed, you can use a parameter to say not to install the CRD:

```console
helm install msi-acrpull msi-acrpull/msi-acrpull --set=installCRDs=false
```