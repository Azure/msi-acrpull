targetScope = 'subscription'

param location string

resource resourceGroup 'Microsoft.Resources/resourceGroups@2024-03-01' = {
    name: 'msi-acrpull-e2e-test-runner'
    location: location
}

module identity 'identity.bicep' = {
    scope: resourceGroup
    name: 'msi-acrpull-e2e-test-runner'
    params: {
        location: resourceGroup.location
    }
}

// Contributor:
// https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/privileged#owner
// https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#privileged
var ownerId = 'b24988ac-6180-42a0-ab88-20f7382dd24c'
resource subOwnerRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
    name: guid(subscription().id, 'msi-acrpull-e2e-test-runner', ownerId)
    scope: subscription()
    properties: {
        roleDefinitionId: resourceId('Microsoft.Authorization/roleDefinitions', ownerId)
        principalType: 'ServicePrincipal'
        principalId: identity.outputs.pullerIdentity.properties.principalId
    }
}


// ACR Owner:
// https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#containers
// https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/containers#azure-container-storage-owner
var acrOwnerId = '95de85bd-744d-4664-9dde-11430bc34793'
resource acrOwnerRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
    name: guid(subscription().id, 'msi-acrpull-e2e-test-runner', acrOwnerId)
    scope: subscription()
    properties: {
        roleDefinitionId: resourceId('Microsoft.Authorization/roleDefinitions', acrOwnerId)
        principalType: 'ServicePrincipal'
        principalId: identity.outputs.pullerIdentity.properties.principalId
    }
}