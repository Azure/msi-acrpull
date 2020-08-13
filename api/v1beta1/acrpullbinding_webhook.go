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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

// log is for logging in this package.
var acrpullbindinglog = logf.Log.WithName("acrpullbinding-resource")

// SetupWebhookWithManager sets up the webhook with the manager
func (r *AcrPullBinding) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// +kubebuilder:webhook:verbs=create;update,path=/validate-msi-acrpull-microsoft-com-v1beta1-acrpullbinding,mutating=false,failurePolicy=fail,groups=msi-acrpull.microsoft.com,resources=acrpullbindings,versions=v1beta1,name=vacrpullbinding.kb.io

var _ webhook.Validator = &AcrPullBinding{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *AcrPullBinding) ValidateCreate() error {
	acrpullbindinglog.Info("validate create", "name", r.Name)

	// TODO(user): fill in your validation logic upon object creation.
	return nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *AcrPullBinding) ValidateUpdate(oldRaw runtime.Object) error {
	acrpullbindinglog.Info("validate update", "name", r.Name)
	var allErrs field.ErrorList

	old := oldRaw.(*AcrPullBinding)

	if errs := validateServiceAccountName(old.Spec.ServiceAccountName, r.Spec.ServiceAccountName, field.NewPath("serviceAccountName")); len(errs) > 0 {
		allErrs = append(allErrs, errs...)
	}
	if len(allErrs) == 0 {
		return nil
	}

	return apierrors.NewInvalid(
		schema.GroupKind{Group: "msi-acrpull.microsoft.com", Kind: "AcrPullBinding"},
		r.Name, allErrs)
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *AcrPullBinding) ValidateDelete() error {
	acrpullbindinglog.Info("validate delete", "name", r.Name)

	// TODO(user): fill in your validation logic upon object deletion.
	return nil
}

func validateServiceAccountName(old, new string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if old != new {
		allErrs = append(allErrs, field.Invalid(fieldPath, new, "changing associated service account after acr pull binding creation is not allowed"))
	}
	return allErrs
}
