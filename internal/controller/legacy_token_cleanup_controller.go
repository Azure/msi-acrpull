package controller

import (
	"context"
	"os"
	"slices"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/util/sets"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
)

const (
	pullBindingField      = ".pullBinding"
	serviceAccountField   = ".spec.serviceAccountName"
	imagePullSecretsField = ".imagePullSecrets"
)

func indexPullBindingByServiceAccount(object client.Object) []string {
	acrPullBinding, ok := object.(*msiacrpullv1beta1.AcrPullBinding)
	if !ok {
		return nil
	}

	return []string{getServiceAccountName(acrPullBinding.Spec.ServiceAccountName)}
}

func enqueuePullBindingsForServiceAccount(mgr ctrl.Manager) func(ctx context.Context, object client.Object) []reconcile.Request {
	return func(ctx context.Context, object client.Object) []reconcile.Request {
		var pullBindings msiacrpullv1beta1.AcrPullBindingList
		if err := mgr.GetClient().List(ctx, &pullBindings, client.InNamespace(object.GetNamespace()), client.MatchingFields{serviceAccountField: object.GetName()}); err != nil {
			return nil
		}
		var requests []reconcile.Request
		for _, pullBinding := range pullBindings.Items {
			requests = append(requests, reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(&pullBinding),
			})
		}
		return requests
	}
}

type LegacyTokenCleanupController struct {
	Client client.Client
	Log    logr.Logger
}

func (c *LegacyTokenCleanupController) SetupWithManager(_ context.Context, mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("legacy-token-cleanup").
		For(&msiacrpullv1beta1.AcrPullBinding{}).
		Complete(c)
}

// Reconcile cleans up legacy ACR pull token secrets and references to them from the cluster if new tokens have
// been generated.
func (c *LegacyTokenCleanupController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := c.Log.WithValues("acrpullbinding", req.NamespacedName)

	acrBinding := &msiacrpullv1beta1.AcrPullBinding{}
	if err := c.Client.Get(ctx, req.NamespacedName, acrBinding); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "unable to fetch acrPullBinding.")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	legacySecret := &corev1.Secret{}
	if err := c.Client.Get(ctx, types.NamespacedName{
		Namespace: req.Namespace,
		Name:      legacySecretName(acrBinding.ObjectMeta.Name),
	}, legacySecret); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "failed to get legacy secret")
			return ctrl.Result{}, err
		} else {
			legacySecret = nil
		}
	}
	action := c.reconcile(acrBinding, legacySecret)

	return c.execute(ctx, action)
}

func (c *LegacyTokenCleanupController) reconcile(acrBinding *msiacrpullv1beta1.AcrPullBinding, legacySecret *corev1.Secret) *cleanupAction {
	if legacySecret != nil {
		if _, labelled := legacySecret.Labels[ACRPullBindingLabel]; labelled {
			// legacy secret already labelled, so there's nothing left to do for this pull binding. In this case, it is
			// possible that every object that required cleanup is already gone; in which case we should exit the
			// process, so the Pod that succeeds us can filter the informers used to drive the controller and stop
			// having to track extraneous objects
			c.Log.Info("checking to see if legacy token cleanup is complete")
			return &cleanupAction{checkCompletion: true}
		}

		updated := legacySecret.DeepCopy()
		if updated.Labels == nil {
			updated.Labels = map[string]string{}
		}
		updated.Labels[ACRPullBindingLabel] = acrBinding.GetName()
		c.Log.WithValues("secretNamespace", updated.Namespace, "secretName", updated.Name).Info("adding label to pull secret")
		return &cleanupAction{updateSecret: updated}
	}
	// legacy secret gone, so there's nothing left to do for this pull binding. In this case, it is
	// possible that every object that required cleanup is already gone; in which case we should exit the
	// process, so the Pod that succeeds us can filter the informers used to drive the controller and stop
	// having to track extraneous objects
	c.Log.Info("checking to see if legacy token cleanup is complete")
	return &cleanupAction{checkCompletion: true}
}

func (c *LegacyTokenCleanupController) execute(ctx context.Context, action *cleanupAction) (ctrl.Result, error) {
	if action == nil {
		return ctrl.Result{}, nil
	}
	action.validate()
	if action.updateSecret != nil {
		return ctrl.Result{}, c.Client.Update(ctx, action.updateSecret)
	} else if action.checkCompletion {
		return ctrl.Result{}, c.checkCompletion(ctx)
	}
	return ctrl.Result{}, nil
}

type cleanupAction struct {
	updateSecret    *corev1.Secret
	checkCompletion bool
}

func (a *cleanupAction) validate() {
	var present int
	if a.updateSecret != nil {
		present++
	}
	if a.checkCompletion {
		present++
	}
	if present > 1 {
		panic("programmer error: more than one action specified in reconciliation loop")
	}
}

func (c *LegacyTokenCleanupController) checkCompletion(ctx context.Context) error {
	var pullBindings msiacrpullv1beta1.AcrPullBindingList
	if err := c.Client.List(ctx, &pullBindings); err != nil {
		return err
	}

	var secrets corev1.SecretList
	if err := c.Client.List(ctx, &secrets); err != nil {
		return err
	}

	if !LegacyPullSecretsPresentWithoutLabels(pullBindings, secrets) {
		c.Log.Info("no more legacy pull secrets present, restarting...")
		os.Exit(0)
	}
	return nil
}

// LegacyPullSecretsPresentWithoutLabels determines if any legacy pull secrets still exist on the cluster without labels.
func LegacyPullSecretsPresentWithoutLabels(pullBindings msiacrpullv1beta1.AcrPullBindingList, secrets corev1.SecretList) bool {
	secretNames := sets.Set[string]{}
	for _, pullBinding := range pullBindings.Items {
		secretNames.Insert(legacySecretName(pullBinding.ObjectMeta.Name))
	}

	return slices.ContainsFunc(secrets.Items, func(secret corev1.Secret) bool {
		_, labelled := secret.Labels[ACRPullBindingLabel]
		return secretNames.Has(secret.ObjectMeta.Name) && !labelled
	})
}
