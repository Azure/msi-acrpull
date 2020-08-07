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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AcrPullBindingSpec defines the desired state of AcrPullBinding
type AcrPullBindingSpec struct {
	// +kubebuilder:validation:MinLength=0

	// The full server name for the ACR. For example, test.azurecr.io
	AcrServer string `json:"acrServer,omitempty"`

	// +kubebuilder:validation:MinLength=0

	// The Managed Identity client ID that is used to authenticate with ACR
	MsiClientID string `json:"msiClientId"`
}

// AcrPullBindingStatus defines the observed state of AcrPullBinding
type AcrPullBindingStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Information when was the last time the ACR token was refreshed.
	// +optional
	LastTokenRefreshTime *metav1.Time `json:"lastTokenRefreshTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// AcrPullBinding is the Schema for the acrpullbindings API
type AcrPullBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AcrPullBindingSpec   `json:"spec,omitempty"`
	Status AcrPullBindingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AcrPullBindingList contains a list of AcrPullBinding
type AcrPullBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AcrPullBinding `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AcrPullBinding{}, &AcrPullBindingList{})
}
