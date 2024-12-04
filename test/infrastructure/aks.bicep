@description('Concatenation of inputs which, when taken together, will uniquely identify this environment. Used to derive names in this template.')
param uniqueIdentifier string
param location string = resourceGroup().location
param pullerIdentityName string

resource controlPlaneIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: guid(uniqueIdentifier, 'controlPlane')
  location: location
}

// Azure Key Vault Secrets User
// https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/security#key-vault-secrets-user
// https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/security
var keyVaultSecretsUserId = '4633458b-17de-408a-b874-0445c86b69e6'
resource controlPlaneAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(uniqueIdentifier, resourceGroup().id, controlPlaneIdentity.id, keyVaultSecretsUserId)
  scope: resourceGroup()
  properties: {
    roleDefinitionId: resourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsUserId)
    principalType: 'ServicePrincipal'
    principalId: controlPlaneIdentity.properties.principalId
  }
}

resource aks 'Microsoft.ContainerService/managedClusters@2024-06-02-preview' = {
  name: guid(uniqueIdentifier, 'aks')
  location: location
  sku: {
    name: 'Base'
    tier: 'Free'
  }
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${controlPlaneIdentity.id}': {}
    }
  }
  properties: {
    kubernetesVersion: '1.30.6'
    securityProfile: {
      workloadIdentity: {
        enabled: true
      }
    }
    oidcIssuerProfile: {
      enabled: true
    }
    aadProfile: {
      managed: true
      enableAzureRBAC: true
    }
    agentPoolProfiles: [
      {
        name: 'system'
        mode: 'System'
        osType: 'Linux'
        vmSize: 'Standard_D2S_v3'
        count: 1
      }
      {
        name: 'user'
        mode: 'User'
        osType: 'Linux'
        vmSize: 'Standard_D2S_v3'
        count: 1
      }
    ]
    autoUpgradeProfile: {
      nodeOSUpgradeChannel: 'NodeImage'
      upgradeChannel: 'node-image'
    }
    dnsPrefix: uniqueString(uniqueIdentifier)
  }
}

resource pullerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: pullerIdentityName
}

// We need to serialize the creation of these FICs to stop concurrent detection errors:
// https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-considerations#concurrent-updates-arent-supported-user-assigned-managed-identities

resource federatedCredentialSuccess 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = {
  name: guid(aks.id, pullerIdentity.id, 'success')
  parent: pullerIdentity
  properties: {
    audiences: [
      'api://AzureCRTokenExchange'
    ]
    issuer: aks.properties.oidcIssuerProfile.issuerURL
    subject: 'system:serviceaccount:v1beta2-wi-success:sa'
  }
}

resource federatedCredentialMutation 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = {
  name: guid(aks.id, pullerIdentity.id, 'mutation')
  parent: pullerIdentity
  properties: {
    audiences: [
      'api://AzureCRTokenExchange'
    ]
    issuer: aks.properties.oidcIssuerProfile.issuerURL
    subject: 'system:serviceaccount:v1beta2-wi-mutation:sa'
  }
  dependsOn: [federatedCredentialSuccess]
}

resource federatedCredentialScoped 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = {
  name: guid(aks.id, pullerIdentity.id, 'scoped')
  parent: pullerIdentity
  properties: {
    audiences: [
      'api://AzureCRTokenExchange'
    ]
    issuer: aks.properties.oidcIssuerProfile.issuerURL
    subject: 'system:serviceaccount:v1beta2-wi-scoped:sa'
  }
  dependsOn: [federatedCredentialMutation]
}

output aks string = aks.name
