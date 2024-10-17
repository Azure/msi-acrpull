targetScope = 'resourceGroup'
param location string = resourceGroup().location

resource pullerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
    name: guid('msi-acrpull-e2e-runner')
    location: location
}

// Issuer: https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect#understanding-the-oidc-token
// Audience: https://learn.microsoft.com/en-us/azure/developer/github/connect-from-azure-openid-connect#set-up-azure-login-action-with-openid-connect-in-github-actions-workflows
// Subject: https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect#filtering-for-pull_request-events
resource credential 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = {
  name: 'msi-acrpull-e2e-test-runner'
  parent: pullerIdentity
  properties: {
    audiences: [
      'api://AzureADTokenExchange'
    ]
    issuer: 'https://token.actions.githubusercontent.com'
    subject: 'repo:Azure/msi-acrpull:pull_request'
  }
}

output pullerIdentity object = pullerIdentity