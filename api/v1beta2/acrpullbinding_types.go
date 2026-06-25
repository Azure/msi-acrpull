/*
   MIT License

   Copyright (c) Microsoft Corporation.

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE
*/

package v1beta2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AcrPullBindingSpec defines the desired state of AcrPullBinding
type AcrPullBindingSpec struct {
	// +kubebuilder:validation:Required

	// ACR holds specifics of the Azure Container Registry for which credentials are projected.
	ACR AcrConfiguration `json:"acr,omitempty"`

	// +kubebuilder:validation:Required

	// Auth determines how we will authenticate to the Azure Container Registry. Only one method may be provided.
	Auth AuthenticationMethod `json:"auth,omitempty"`

	// +kubebuilder:validation:Required

	// The name of the service account to associate the image pull secret with.
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="self.environment == 'ArigappedCloud' ? has(self.cloudConfig) : !has(self.cloudConfig)", message="a custom cloud configuration must be present for air-gapped cloud environments"

// AcrConfiguration identifies the Azure Container Registry we wish to bind to and how we will bind to it.
type AcrConfiguration struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:example=example.azurecr.io
	// +kubebuilder:validation:XValidation:rule="isURL('https://' + self) && url('https://' + self).getHostname() == self", message="server must be a fully-qualified domain name"

	// Server is the FQDN for the Azure Container Registry, e.g. example.azurecr.io
	Server string `json:"server"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:example="repository:my-repository:pull,push"

	// Scope defines the scope for the access token, e.g. pull/push access for a repository.
	// Note: you need to pin it down to the repository level, there is no wildcard available,
	// however a list of space-delimited scopes is acceptable.
	// See docs for details: https://distribution.github.io/distribution/spec/auth/scope/
	//
	// Examples:
	// repository:my-repository:pull,push
	// repository:my-repository:pull repository:other-repository:push,pull
	Scope string `json:"scope"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=PublicCloud;USGovernmentCloud;ChinaCloud;AirgappedCloud
	// +kubebuilder:default=PublicCloud
	// +kubebuilder:example=PublicCloud

	// Environment specifies the Azure Cloud environment in which the ACR is deployed.
	Environment AzureEnvironmentType `json:"environment"`

	// +kubebuilder:validation:Optional

	// AirgappedCloudConfiguration configures a custom cloud to interact with when running air-gapped.
	CloudConfig *AirgappedCloudConfiguration `json:"cloudConfig,omitempty"`
}

// AzureEnvironmentType represents a set of endpoints for each of Azure's Clouds.
type AzureEnvironmentType string

const (
	AzureEnvironmentPublicCloud       AzureEnvironmentType = "PublicCloud"
	AzureEnvironmentUSGovernmentCloud AzureEnvironmentType = "USGovernmentCloud"
	AzureEnvironmentChinaCloud        AzureEnvironmentType = "ChinaCloud"
	AzureEnvironmentAirgappedCloud    AzureEnvironmentType = "AirgappedCloud"
)

type AirgappedCloudConfiguration struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1

	// EntraAuthorityHost configures a custom Entra host endpoint.
	EntraAuthorityHost string `json:"entraAuthorityHost"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1

	// ResourceManagerAudience configures the audience for which tokens will be requested from Entra.
	ResourceManagerAudience string `json:"resourceManagerAudience"`
}

// +kubebuilder:validation:XValidation:rule="[has(self.managedIdentity), has(self.workloadIdentity)].exists_one(x, x)", message="only one authentication type can be set"

// AuthenticationMethod holds a disjoint set of methods for authentication to an ACR.
type AuthenticationMethod struct {
	// +kubebuilder:validation:Optional

	// ManagedIdentity uses Azure Managed Identity to authenticate with Azure.
	ManagedIdentity *ManagedIdentityAuth `json:"managedIdentity,omitempty"`

	// +kubebuilder:validation:Optional

	// WorkloadIdentity uses Azure Workload Identity to authenticate with Azure.
	WorkloadIdentity *WorkloadIdentityAuth `json:"workloadIdentity,omitempty"`

	// +kubebuilder:validation:Optional

	// Federated Identity Creationals for Cross Cloud
	FederatedIdentity *FederatedIdentityAuth `json:"federatedIdentity,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="[has(self.clientID), has(self.resourceID)].exists_one(x, x)", message="only client or resource ID can be set"

// ManagedIdentityAuth configures authentication to use a managed identity.
type ManagedIdentityAuth struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:example="1b461305-28be-5271-beda-bd9fd2e24251"

	// ClientID is the client identifier for the managed identity. Either provide the client ID or the resource ID.
	ClientID string `json:"clientID,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:example=/subscriptions/sub-name/resourceGroups/rg-name/providers/Microsoft.ManagedIdentity/userAssignedIdentities/1b461305-28be-5271-beda-bd9fd2e24251

	// ResourceID is the resource identifier for the managed identity. Either provide the client ID or the resource ID.
	ResourceID string `json:"resourceID,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="(has(self.clientID) && has(self.tenantID)) || (!has(self.clientID) && !has(self.tenantID))", message="custom client and tenant identifiers must be provided together, if at all"

type WorkloadIdentityAuth struct {
	// +kubebuilder:validation:Required

	// ServiceAccountName specifies the name of the service account
	// that should be used when authenticating with WorkloadIdentity.
	ServiceAccountName string `json:"serviceAccountRef,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:example="1b461305-28be-5271-beda-bd9fd2e24251"

	// ClientID holds an optional client identifier of a federated identity.
	// Specify this identifier if multiple identities are federated with the
	// service account and the identity to use for image pulling is not the
	// default identity stored in the service account's annotations. The
	// client and tenant ID must be specified together.
	ClientID string `json:"clientID,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:example="72f988bf-86f1-41af-91ab-2d7cd011db47"

	// TenantID holds an optional tenant identifier of a federated identity.
	// Specify this identifier if multiple identities are federated with the
	// service account and the identity to use for image pulling is not the
	// default identity stored in the service account's annotations. The
	// client and tenant ID must be specified together.
	TenantID string `json:"tenantID,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="(has(self.sourceClientID) && has(self.SourceTenantID))", message="custom client and tenant identifiers must be provided together, if at all"

type FederatedIdentityAuth struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:example="1b461305-28be-5271-beda-bd9fd2e24251"

	// SourceClienTid holds the identified of identity residing on the tenant where request has been made.
	SourceClientID string `json:"sourceClientID,omitempty"`

	// +kubebuilder:validation:Required
	// +kubebuilder:example="72f988bf-86f1-41af-91ab-2d7cd011db47"

	// TenantID holds an optional tenant identifier of a federated identity.
	// Specify this identifier if multiple identities are federated with the
	// service account and the identity to use for image pulling is not the
	// default identity stored in the service account's annotations. The
	// client and tenant ID must be specified together.
	SourceTenantID string `json:"sourceTenantID,omitempty"`

	// +kubebuilder:validation:Required
	// +kubebuilder:example="1b461305-28be-5271-beda-bd9fd2e24251"

	// ClientID holds an optional client identifier of a federated identity.
	// Specify this identifier if multiple identities are federated with the
	// service account and the identity to use for image pulling is not the
	// default identity stored in the service account's annotations. The
	// client and tenant ID must be specified together.
	TargetClientID string `json:"targetClientID,omitempty"`

	// +kubebuilder:validation:Required
	// +kubebuilder:example="72f988bf-86f1-41af-91ab-2d7cd011db47"

	// TenantID holds an optional tenant identifier of a federated identity.
	// Specify this identifier if multiple identities are federated with the
	// service account and the identity to use for image pulling is not the
	// default identity stored in the service account's annotations. The
	// client and tenant ID must be specified together.
	TargetTenantID string `json:"targetTenantID,omitempty"`

	// +kubebuilder:validation:Required
	// +kubebuilder:example="72f988bf-86f1-41af-91ab-2d7cd011db47"

	// TenantID holds an optional tenant identifier of a federated identity.
	// Specify this identifier if multiple identities are federated with the
	// service account and the identity to use for image pulling is not the
	// default identity stored in the service account's annotations. The
	// client and tenant ID must be specified together.
	Scope string `json:"scope,omitempty"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=PublicCloud;USGovernmentCloud;ChinaCloud;AirgappedCloud
	// +kubebuilder:default=PublicCloud
	// +kubebuilder:example=PublicCloud

	// Environment specifies the Azure Cloud environment in which the ACR is deployed.
	TargetEnvironment AzureEnvironmentType `json:"targetEnvironment,omitempty"`
}

// AcrPullBindingStatus defines the observed state of AcrPullBinding
type AcrPullBindingStatus struct {
	// +kubebuilder:validation:Optional

	// Information when was the last time the ACR token was refreshed.
	LastTokenRefreshTime *metav1.Time `json:"lastTokenRefreshTime,omitempty"`

	// +kubebuilder:validation:Optional

	// The expiration date of the current ACR token.
	TokenExpirationTime *metav1.Time `json:"tokenExpirationTime,omitempty"`

	// +kubebuilder:validation:Optional

	// Error message if there was an error updating the token.
	Error string `json:"error,omitempty"`
}

// +genclient
// +kubebuilder:resource:path=acrpullbindings,shortName=apb;apbs,scope=Namespaced
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Server",type="string",JSONPath=".spec.acr.server",description="FQDN for the ACR.",priority=0
// +kubebuilder:printcolumn:name="Scope",type="string",JSONPath=".spec.acr.scope",description="Scope for the ACR token.",priority=1
// +kubebuilder:printcolumn:name="Target",type="string",JSONPath=".spec.serviceAccountName",description="ServiceAccount to which the pull credentials are attached.",priority=0
// +kubebuilder:printcolumn:name="Last Refresh",type="date",JSONPath=".status.lastTokenRefreshTime",description="Time the token was last refreshed.",priority=1
// +kubebuilder:printcolumn:name="Expiration",type="date",JSONPath=".status.tokenExpirationTime",description="Time the current token expires.",priority=0
// +kubebuilder:printcolumn:name="Error",type="string",JSONPath=".status.error",description="Errors encountered during token generation, if any.",priority=0

// AcrPullBinding is the Schema for the acrpullbindings API
type AcrPullBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AcrPullBindingSpec   `json:"spec,omitempty"`
	Status AcrPullBindingStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AcrPullBindingList contains a list of AcrPullBinding
type AcrPullBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AcrPullBinding `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AcrPullBinding{}, &AcrPullBindingList{})
}
