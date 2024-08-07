package controller

import (
	"context"
	"os"
	"slices"

	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
)

const (
	serviceAccountField = ".spec.serviceAccountName"
)

type LegacyTokenCleanupController struct {
	Client client.Client
	Log    logr.Logger
}

func (c *LegacyTokenCleanupController) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(ctx, &msiacrpullv1beta1.AcrPullBinding{}, serviceAccountField, func(object client.Object) []string {
		acrPullBinding, ok := object.(*msiacrpullv1beta1.AcrPullBinding)
		if !ok {
			return nil
		}

		return []string{getServiceAccountName(acrPullBinding.Spec.ServiceAccountName)}
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&msiacrpullv1beta1.AcrPullBinding{}).
		Watches(&corev1.ServiceAccount{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, object client.Object) []reconcile.Request {
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
		})).
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

	serviceAccountName := getServiceAccountName(acrBinding.Spec.ServiceAccountName)
	serviceAccount := &corev1.ServiceAccount{}
	if err := c.Client.Get(ctx, types.NamespacedName{
		Namespace: req.Namespace,
		Name:      serviceAccountName,
	}, serviceAccount); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "failed to get service account")
			return ctrl.Result{}, err
		}
	}

	legacySecret := &corev1.Secret{}
	if err := c.Client.Get(ctx, types.NamespacedName{
		Namespace: req.Namespace,
		Name:      legacySecretName(acrBinding.ObjectMeta.Name),
	}, legacySecret); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "failed to get legacy secret")
			return ctrl.Result{}, err
		}
	}
	action := c.reconcile(acrBinding, serviceAccount, legacySecret)

	return c.execute(ctx, action)
}

func (c *LegacyTokenCleanupController) reconcile(acrBinding *msiacrpullv1beta1.AcrPullBinding, serviceAccount *corev1.ServiceAccount, legacySecret *corev1.Secret) *cleanupAction {
	if !slices.ContainsFunc(serviceAccount.ImagePullSecrets, func(reference corev1.LocalObjectReference) bool {
		return reference.Name == pullSecretName(acrBinding.ObjectMeta.Name)
	}) {
		// this service account doesn't have a non-legacy pull token generated yet, so we shouldn't remove anything
		return nil
	}

	if slices.ContainsFunc(serviceAccount.ImagePullSecrets, func(reference corev1.LocalObjectReference) bool {
		return reference.Name == legacySecretName(acrBinding.ObjectMeta.Name)
	}) {
		// this service account still refers to the legacy token, we need to clean that up
		updated := serviceAccount.DeepCopy()
		updated.ImagePullSecrets = slices.DeleteFunc(updated.ImagePullSecrets, func(reference corev1.LocalObjectReference) bool {
			return reference.Name == legacySecretName(acrBinding.ObjectMeta.Name)
		})
		return &cleanupAction{updateServiceAccount: updated}
	}

	if legacySecret == nil {
		// legacy secret already gone, so there's nothing left to do for this pull binding. In this case, it is
		// possible that every object that required cleanup is already gone; in which case we should exit the
		// process, so the Pod that succeeds us can filter the informers used to drive the controller and stop
		// having to track extraneous objects
		return &cleanupAction{checkCompletion: true}
	}

	// legacy secret still exists, let's clean it up
	return &cleanupAction{deleteSecret: legacySecret}
}

func (c *LegacyTokenCleanupController) execute(ctx context.Context, action *cleanupAction) (ctrl.Result, error) {
	if action == nil {
		return ctrl.Result{}, nil
	}
	action.validate()
	if action.updateServiceAccount != nil {
		return ctrl.Result{}, c.Client.Update(ctx, action.updateServiceAccount)
	} else if action.deleteSecret != nil {
		return ctrl.Result{}, c.Client.Delete(ctx, action.deleteSecret)
	} else if action.checkCompletion {
		return ctrl.Result{}, c.checkCompletion(ctx)
	}
	return ctrl.Result{}, nil
}

type cleanupAction struct {
	updateServiceAccount *corev1.ServiceAccount
	deleteSecret         *corev1.Secret
	checkCompletion      bool
}

func (a *cleanupAction) validate() {
	var present int
	if a.updateServiceAccount != nil {
		present++
	}
	if a.deleteSecret != nil {
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

	if !LegacyPullSecretsPresent(pullBindings, secrets) {
		c.Log.Info("no more legacy pull secrets present, restarting...")
		os.Exit(0)
	}
	return nil
}

// LegacyPullSecretsPresent determines if any legacy pull secrets still exist on the cluster.
func LegacyPullSecretsPresent(pullBindings msiacrpullv1beta1.AcrPullBindingList, secrets corev1.SecretList) bool {
	for _, pullBinding := range pullBindings.Items {
		if slices.ContainsFunc(secrets.Items, func(secret corev1.Secret) bool {
			return secret.Name == legacySecretName(pullBinding.ObjectMeta.Name)
		}) {
			return true
		}
	}
	return false
}
