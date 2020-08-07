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

package controllers

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"time"

	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
)

var (
	jobOwnerKey = ".metadata.controller"
)

// AcrPullBindingReconciler reconciles a AcrPullBinding object
type AcrPullBindingReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=msi-acrpull.microsoft.com,resources=acrpullbindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=msi-acrpull.microsoft.com,resources=acrpullbindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;update;patch

func (r *AcrPullBindingReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("acrpullbinding", req.NamespacedName)

	var acrPullBinding msiacrpullv1beta1.AcrPullBinding
	if err := r.Get(ctx, req.NamespacedName, &acrPullBinding); err != nil {
		log.Error(err, "unable to fetch acrPullBinding.")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	var pullSecrets v1.SecretList
	if err := r.List(ctx, &pullSecrets, client.InNamespace(req.Namespace), client.MatchingFields{jobOwnerKey: req.Name}); err != nil {
		log.Error(err, "unable to list child Jobs")
		return ctrl.Result{}, err
	}

	if len(pullSecrets.Items) > 1 {
		err := errors.New("more than 1 secret registered to thsi CRD")
		return ctrl.Result{}, err
	}

	if len(pullSecrets.Items) == 0 {
		pullSecret := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Labels: make(map[string]string),
				Annotations: map[string]string{
					"sam.io": "new",
				},
				Name:      fmt.Sprintf("%s-msi-acrpull-secret", acrPullBinding.Name),
				Namespace: acrPullBinding.Namespace,
			},
		}

		if err := ctrl.SetControllerReference(&acrPullBinding, pullSecret, r.Scheme); err != nil {
			log.Error(err, "failed to create Acr ImagePullSecret")
			return ctrl.Result{}, err
		}

		if err := r.Create(ctx, pullSecret); err != nil {
			log.Error(err, "Failed to create pull secret")
			return ctrl.Result{}, err
		}

		return ctrl.Result{
			RequeueAfter: time.Minute * 10,
		}, nil
	}

	pullSecret := &pullSecrets.Items[0]
	pullSecret.Annotations["sam.io"] = time.Now().String()

	if err := r.Update(ctx, pullSecret); err != nil {
		log.Error(err, "Failed to update pull secret")
		return ctrl.Result{}, err
	}

	return ctrl.Result{
		RequeueAfter: time.Minute * 10,
	}, nil
}

func (r *AcrPullBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(&v1.Secret{}, jobOwnerKey, func(rawObj runtime.Object) []string {
		// grab the job object, extract the owner...
		secret := rawObj.(*v1.Secret)
		owner := metav1.GetControllerOf(secret)
		if owner == nil {
			return nil
		}

		// ...make sure it's a CronJob...
		if owner.APIVersion != msiacrpullv1beta1.GroupVersion.String() || owner.Kind != "AcrPullBinding" {
			return nil
		}

		// ...and if so, return it
		return []string{owner.Name}
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&msiacrpullv1beta1.AcrPullBinding{}).
		Owns(&v1.Secret{}).
		Complete(r)
}
