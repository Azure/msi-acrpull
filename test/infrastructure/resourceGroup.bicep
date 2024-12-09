targetScope = 'subscription'

@description('Concatenation of inputs which, when taken together, will uniquely identify this environment. Used to derive names in this template.')
param uniqueIdentifier string

param location string

resource testResourceGroup 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: uniqueString(uniqueIdentifier, 'resourceGroup')
  location: location
}

output resourceGroup string = testResourceGroup.name

module acr 'acr.bicep' = {
  scope: testResourceGroup
  name: 'testAcr'
  params: {
    uniqueIdentifier: uniqueIdentifier
    location: testResourceGroup.location
  }
}

output acr object = acr.outputs

module aks 'aks.bicep' = {
  scope: testResourceGroup
  name: 'testAks'
  params: {
    uniqueIdentifier: uniqueIdentifier
    location: testResourceGroup.location
    pullerIdentityName: acr.outputs.pullerIdentityName
  }
}

output aks object = aks.outputs
