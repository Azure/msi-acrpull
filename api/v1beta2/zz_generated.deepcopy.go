//go:build !ignore_autogenerated

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

// Code generated by controller-gen. DO NOT EDIT.

package v1beta2

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AcrConfiguration) DeepCopyInto(out *AcrConfiguration) {
	*out = *in
	if in.CloudConfig != nil {
		in, out := &in.CloudConfig, &out.CloudConfig
		*out = new(AirgappedCloudConfiguration)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AcrConfiguration.
func (in *AcrConfiguration) DeepCopy() *AcrConfiguration {
	if in == nil {
		return nil
	}
	out := new(AcrConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AcrPullBinding) DeepCopyInto(out *AcrPullBinding) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AcrPullBinding.
func (in *AcrPullBinding) DeepCopy() *AcrPullBinding {
	if in == nil {
		return nil
	}
	out := new(AcrPullBinding)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AcrPullBinding) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AcrPullBindingList) DeepCopyInto(out *AcrPullBindingList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]AcrPullBinding, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AcrPullBindingList.
func (in *AcrPullBindingList) DeepCopy() *AcrPullBindingList {
	if in == nil {
		return nil
	}
	out := new(AcrPullBindingList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AcrPullBindingList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AcrPullBindingSpec) DeepCopyInto(out *AcrPullBindingSpec) {
	*out = *in
	in.ACR.DeepCopyInto(&out.ACR)
	in.Auth.DeepCopyInto(&out.Auth)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AcrPullBindingSpec.
func (in *AcrPullBindingSpec) DeepCopy() *AcrPullBindingSpec {
	if in == nil {
		return nil
	}
	out := new(AcrPullBindingSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AcrPullBindingStatus) DeepCopyInto(out *AcrPullBindingStatus) {
	*out = *in
	if in.LastTokenRefreshTime != nil {
		in, out := &in.LastTokenRefreshTime, &out.LastTokenRefreshTime
		*out = (*in).DeepCopy()
	}
	if in.TokenExpirationTime != nil {
		in, out := &in.TokenExpirationTime, &out.TokenExpirationTime
		*out = (*in).DeepCopy()
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AcrPullBindingStatus.
func (in *AcrPullBindingStatus) DeepCopy() *AcrPullBindingStatus {
	if in == nil {
		return nil
	}
	out := new(AcrPullBindingStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AirgappedCloudConfiguration) DeepCopyInto(out *AirgappedCloudConfiguration) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AirgappedCloudConfiguration.
func (in *AirgappedCloudConfiguration) DeepCopy() *AirgappedCloudConfiguration {
	if in == nil {
		return nil
	}
	out := new(AirgappedCloudConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AuthenticationMethod) DeepCopyInto(out *AuthenticationMethod) {
	*out = *in
	if in.ManagedIdentity != nil {
		in, out := &in.ManagedIdentity, &out.ManagedIdentity
		*out = new(ManagedIdentityAuth)
		**out = **in
	}
	if in.WorkloadIdentity != nil {
		in, out := &in.WorkloadIdentity, &out.WorkloadIdentity
		*out = new(WorkloadIdentityAuth)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuthenticationMethod.
func (in *AuthenticationMethod) DeepCopy() *AuthenticationMethod {
	if in == nil {
		return nil
	}
	out := new(AuthenticationMethod)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ManagedIdentityAuth) DeepCopyInto(out *ManagedIdentityAuth) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ManagedIdentityAuth.
func (in *ManagedIdentityAuth) DeepCopy() *ManagedIdentityAuth {
	if in == nil {
		return nil
	}
	out := new(ManagedIdentityAuth)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkloadIdentityAuth) DeepCopyInto(out *WorkloadIdentityAuth) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkloadIdentityAuth.
func (in *WorkloadIdentityAuth) DeepCopy() *WorkloadIdentityAuth {
	if in == nil {
		return nil
	}
	out := new(WorkloadIdentityAuth)
	in.DeepCopyInto(out)
	return out
}
