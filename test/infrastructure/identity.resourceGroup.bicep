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

// RBAC Administrator:
// https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/privileged#role-based-access-control-administrator
// https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#privileged
var rbacAdministratorId = 'f58310d9-a9f6-439a-9e8d-f62e7b41a168'
resource rbacAdministratorRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
    name: guid('acr-puller-assigner', rbacAdministratorId)
    scope: subscription()
    properties: {
        conditionVersion: '2.0'
        condition: '((!(ActionMatches{\'Microsoft.Authorization/roleAssignments/write\'})) OR (@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals{7f951dda4ed34680a7ca43fe172d538d,4633458b17de408ab8740445c86b69e6})) AND ((!(ActionMatches{\'Microsoft.Authorization/roleAssignments/delete\'})) OR (@Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals{7f951dda4ed34680a7ca43fe172d538d,4633458b17de408ab8740445c86b69e6}))'
        roleDefinitionId: resourceId('Microsoft.Authorization/roleDefinitions', rbacAdministratorId)
        principalType: 'ServicePrincipal'
        principalId: identity.outputs.pullerIdentity.properties.principalId
    }
}
