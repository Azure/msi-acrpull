@description('Concatenation of inputs which, when taken together, will uniquely identify this environment. Used to derive names in this template.')
param uniqueIdentifier string
param location string = resourceGroup().location

@description('The service registry holds the MSI-ACRPull built images from this test and needs to be open for unauthenticated pulls.')
resource serviceRegistry 'Microsoft.ContainerRegistry/registries@2023-01-01-preview' = {
  name: uniqueString(uniqueIdentifier, 'service-acr')
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    anonymousPullEnabled: true
  }
}

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

output registryName string = registry.name
output serviceRegistryName string = serviceRegistry.name
output pullerIdentity string = pullerIdentity.id
output pullerIdentityName string = pullerIdentity.name
output pullerIdentityClientId string = pullerIdentity.properties.clientId
