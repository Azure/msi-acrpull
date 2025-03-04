package controller

import (
	"context"
	"fmt"
	"slices"
	"time"

	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
	msiacrpullv1beta2 "github.com/Azure/msi-acrpull/api/v1beta2"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// genericReconciler reconciles AcrPullBindings
type genericReconciler[O pullBinding] struct {
	Client crclient.Client
	Logger logr.Logger
	Scheme *runtime.Scheme

	NewBinding func() O

	AddFinalizer    func(O, string) O
	RemoveFinalizer func(O, string) O

	GetServiceAccountName func(O) string
	GetPullSecretName     func(O) string
	GetInputsHash         func(O) string

	CreatePullCredential func(context.Context, O, *corev1.ServiceAccount) (string, time.Time, error)

	UpdateStatusError func(O, string) O

	NeedsRefresh func(logr.Logger, *corev1.Secret, func() time.Time) bool
	RequeueAfter func(now func() time.Time) func(O) time.Duration

	NeedsStatusUpdate func(time.Time, time.Time, O) bool
	UpdateStatus      func(time.Time, time.Time, O) O

	now func() time.Time
}

func (r *genericReconciler[O]) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Logger.WithValues("acrpullbinding", req.NamespacedName)

	acrBinding := r.NewBinding()
	if err := r.Client.Get(ctx, req.NamespacedName, acrBinding); err != nil {
		if !apierrors.IsNotFound(err) {
			msg := "unable to fetch acrPullBinding."
			logger.Error(err, msg)
			return ctrl.Result{}, fmt.Errorf("%s: %w", msg, err)
		}
		return ctrl.Result{}, nil
	}

	serviceAccount := &corev1.ServiceAccount{}
	if err := r.Client.Get(ctx, k8stypes.NamespacedName{
		Namespace: req.Namespace,
		Name:      r.GetServiceAccountName(acrBinding),
	}, serviceAccount); err != nil {
		if !apierrors.IsNotFound(err) {
			msg := "failed to get service account"
			logger.Error(err, msg)
			return ctrl.Result{}, fmt.Errorf("%s: %w", msg, err)
		} else {
			serviceAccount = nil
		}
	}

	var pullSecrets corev1.SecretList
	if err := r.Client.List(ctx, &pullSecrets, crclient.InNamespace(acrBinding.GetNamespace()), crclient.MatchingFields{pullBindingField: acrBinding.GetName()}); err != nil {
		msg := "failed to fetch pull secrets referencing pull binding"
		logger.Error(err, msg)
		return ctrl.Result{}, fmt.Errorf("%s: %w", msg, err)
	}

	var pullSecretNames []string
	if len(pullSecrets.Items) == 0 {
		pullSecretNames = append(pullSecretNames, r.GetPullSecretName(acrBinding))
	} else {
		for _, pullSecret := range pullSecrets.Items {
			pullSecretNames = append(pullSecretNames, pullSecret.ObjectMeta.Name)
		}
	}

	var referencingServiceAccounts []corev1.ServiceAccount
	for _, pullSecret := range pullSecretNames {
		var serviceAccountList corev1.ServiceAccountList
		if err := r.Client.List(ctx, &serviceAccountList, crclient.InNamespace(acrBinding.GetNamespace()), crclient.MatchingFields{imagePullSecretsField: pullSecret}); err != nil {
			msg := "failed to fetch service accounts referencing pull secret"
			logger.Error(err, msg)
			return ctrl.Result{}, fmt.Errorf("%s: %w", msg, err)
		}
		referencingServiceAccounts = append(referencingServiceAccounts, serviceAccountList.Items...)
	}

	action := r.reconcile(ctx, logger, acrBinding, serviceAccount, pullSecrets.Items, referencingServiceAccounts)

	return action.execute(ctx, logger, r.Client, r.RequeueAfter(r.now))
}

func (r *genericReconciler[O]) reconcile(ctx context.Context, logger logr.Logger, acrBinding O, serviceAccount *corev1.ServiceAccount, pullSecrets []corev1.Secret, referencingServiceAccounts []corev1.ServiceAccount) *action[O] {
	// examine DeletionTimestamp to determine if acr pull binding is under deletion
	if acrBinding.GetDeletionTimestamp().IsZero() {
		// the object is not being deleted, so if it does not have our finalizer,
		// then need to add the finalizer and update the object.
		if !slices.Contains(acrBinding.GetFinalizers(), msiAcrPullFinalizerName) {
			logger.Info("adding finalizer to pull binding")
			return &action[O]{updatePullBinding: r.AddFinalizer(acrBinding, msiAcrPullFinalizerName)}
		}
	} else {
		// the object is being deleted, do cleanup as necessary
		return r.cleanUp(acrBinding, serviceAccount, pullSecrets, logger)
	}

	// if the user changed which service account should be bound to this credential, we need to
	// un-bind the credential from any service accounts it was bound to previously
	extraneousServiceAccounts := slices.DeleteFunc(referencingServiceAccounts, func(other corev1.ServiceAccount) bool {
		return serviceAccount != nil && other.Name == serviceAccount.Name
	})
	for _, extraneous := range extraneousServiceAccounts {
		updated := extraneous.DeepCopy()
		updated.ImagePullSecrets = slices.DeleteFunc(updated.ImagePullSecrets, func(reference corev1.LocalObjectReference) bool {
			return reference.Name == r.GetPullSecretName(acrBinding)
		})
		if len(updated.ImagePullSecrets) != len(extraneous.ImagePullSecrets) {
			logger.WithValues("serviceAccount", crclient.ObjectKeyFromObject(&extraneous).String()).Info("updating service account to remove image pull secret")
			return &action[O]{updateServiceAccount: updated}
		}
	}

	if serviceAccount == nil {
		err := fmt.Sprintf("service account %q not found", r.GetServiceAccountName(acrBinding))
		logger.Info(err)
		return &action[O]{updatePullBindingStatus: r.UpdateStatusError(acrBinding, err)}
	}

	expectedPullSecretName := r.GetPullSecretName(acrBinding)
	var pullSecret *corev1.Secret
	for _, secret := range pullSecrets {
		if secret.Name == expectedPullSecretName {
			pullSecret = &secret
		}
	}
	inputHash := r.GetInputsHash(acrBinding)
	pullSecretMissing := pullSecret == nil
	pullSecretNeedsRefresh := !pullSecretMissing && r.NeedsRefresh(r.Logger, pullSecret, r.now)
	pullSecretInputsChanged := !pullSecretMissing && pullSecret.Annotations[tokenInputsAnnotation] != inputHash
	if pullSecretMissing || pullSecretNeedsRefresh || pullSecretInputsChanged {
		logger.WithValues("pullSecretMissing", pullSecretMissing, "pullSecretNeedsRefresh", pullSecretNeedsRefresh, "pullSecretInputsChanged", pullSecretInputsChanged).Info("generating new pull credential")

		dockerConfig, expiresOn, err := r.CreatePullCredential(ctx, acrBinding, serviceAccount)
		if err != nil {
			logger.Info(err.Error())
			return &action[O]{updatePullBindingStatus: r.UpdateStatusError(acrBinding, err.Error())}
		}

		newSecret := newPullSecret(acrBinding, r.GetPullSecretName(acrBinding), dockerConfig, r.Scheme, expiresOn, r.now, inputHash)
		logger = logger.WithValues("secret", crclient.ObjectKeyFromObject(newSecret).String())
		if pullSecret == nil {
			logger.Info("creating pull credential secret")
			return &action[O]{createSecret: newSecret}
		} else {
			logger.Info("updating pull credential secret")
			return &action[O]{updateSecret: newSecret}
		}
	}

	if !slices.ContainsFunc(serviceAccount.ImagePullSecrets, func(reference corev1.LocalObjectReference) bool {
		return reference.Name == pullSecret.Name
	}) {
		updated := serviceAccount.DeepCopy()
		updated.ImagePullSecrets = append(updated.ImagePullSecrets, corev1.LocalObjectReference{
			Name: pullSecret.Name,
		})
		logger.WithValues("serviceAccount", crclient.ObjectKeyFromObject(serviceAccount).String()).Info("updating service account to add image pull secret")
		return &action[O]{updateServiceAccount: updated}
	}

	// clean up any extraneous pull secrets that refer to this binding
	for _, secret := range pullSecrets {
		if secret.ObjectMeta.Name != expectedPullSecretName {
			deleted := secret.DeepCopy()
			logger.WithValues("secret", crclient.ObjectKeyFromObject(deleted).String()).Info("cleaning up extraneous pull credential")
			return &action[O]{deleteSecret: deleted}
		}
	}

	return r.setSuccessStatus(logger, acrBinding, pullSecret)
}

func (r *genericReconciler[O]) cleanUp(acrBinding O,
	serviceAccount *corev1.ServiceAccount, pullSecrets []corev1.Secret, log logr.Logger) *action[O] {
	if slices.Contains(acrBinding.GetFinalizers(), msiAcrPullFinalizerName) {
		// our finalizer is present, so need to clean up ImagePullSecret reference
		if serviceAccount == nil {
			log.Info("service account not found, continuing to remove finalizer")
		} else {
			updated := serviceAccount.DeepCopy()
			updated.ImagePullSecrets = slices.DeleteFunc(updated.ImagePullSecrets, func(reference corev1.LocalObjectReference) bool {
				return reference.Name == r.GetPullSecretName(acrBinding)
			})
			if len(updated.ImagePullSecrets) != len(serviceAccount.ImagePullSecrets) {
				log.WithValues("serviceAccount", crclient.ObjectKeyFromObject(serviceAccount).String()).Info("updating service account to remove image pull secret")
				return &action[O]{updateServiceAccount: updated}
			}
		}

		// remove the secrets
		for _, pullSecret := range pullSecrets {
			deleted := pullSecret.DeepCopy()
			log.WithValues("secret", crclient.ObjectKeyFromObject(deleted).String()).Info("cleaning up pull credential")
			return &action[O]{deleteSecret: deleted}
		}

		// remove our finalizer from the list and update it.
		log.Info("removing finalizer from pull binding")
		return &action[O]{updatePullBinding: r.RemoveFinalizer(acrBinding, msiAcrPullFinalizerName)}
	}
	log.Info("no finalizer present, nothing to do")
	return nil
}

func (r *genericReconciler[O]) setSuccessStatus(log logr.Logger, acrBinding O, pullSecret *corev1.Secret) *action[O] {
	log = log.WithValues("secret", crclient.ObjectKeyFromObject(pullSecret).String())

	// malformed expiry and refresh annotations indicate some other actor corrupted our pull credential secret;
	// we will re-generate it with correct values in the future, at which point we can update the pull binding

	formattedExpiry, annotated := pullSecret.Annotations[tokenExpiryAnnotation]
	if !annotated {
		log.Info("token expiry annotation not present in secret")
		return nil
	}

	expiry, err := time.Parse(time.RFC3339, formattedExpiry)
	if err != nil {
		log.Error(err, "failed to parse expiry annotation")
		return nil
	}

	formattedRefresh, annotated := pullSecret.Annotations[tokenRefreshAnnotation]
	if !annotated {
		log.Info("token refresh annotation not present in secret")
		return nil
	}

	refresh, err := time.Parse(time.RFC3339, formattedRefresh)
	if err != nil {
		log.Error(err, "failed to parse refresh annotation")
		return nil
	}

	if r.NeedsStatusUpdate(refresh, expiry, acrBinding) {
		log.Info("updating pull binding to reflect expiry and refresh time from secret")
		return &action[O]{updatePullBindingStatus: r.UpdateStatus(refresh, expiry, acrBinding)}
	}
	// there's nothing for us to do, but we must make sure that we re-queue for a refresh
	return &action[O]{noop: acrBinding}
}

func (a *action[O]) execute(ctx context.Context, logger logr.Logger, client crclient.Client, refresh func(O) time.Duration) (ctrl.Result, error) {
	if a == nil {
		return ctrl.Result{}, nil
	}
	a.validate()
	if a.updatePullBinding != nil {
		return ctrl.Result{}, client.Update(ctx, a.updatePullBinding)
	} else if a.noop != nil {
		after := clampRequeue(refresh(a.noop))
		logger.WithValues("requeueAfter", after).Info("nothing to do, re-queueing for later processing")
		return ctrl.Result{RequeueAfter: after}, nil
	} else if a.updatePullBindingStatus != nil {
		after := clampRequeue(refresh(a.updatePullBindingStatus))
		logger.WithValues("requeueAfter", after).Info("re-queueing for later processing")
		return ctrl.Result{RequeueAfter: after}, client.Status().Update(ctx, a.updatePullBindingStatus)
	} else if a.createSecret != nil {
		return ctrl.Result{}, client.Create(ctx, a.createSecret)
	} else if a.updateSecret != nil {
		return ctrl.Result{}, client.Update(ctx, a.updateSecret)
	} else if a.deleteSecret != nil {
		return ctrl.Result{}, client.Delete(ctx, a.deleteSecret)
	} else if a.updateServiceAccount != nil {
		return ctrl.Result{}, client.Update(ctx, a.updateServiceAccount)
	}
	logger.Info("no action taken")
	return ctrl.Result{}, nil
}

// clampRequeue ensures that the requeue duration is greater than zero. Since we poll time.Now() more than once during
// reconciliation, it may be possible to have the following sets of events:
// t_refresh is when the credential should be refreshed based on our calculations
// 1. t_now = t_refresh - 1 : r.NeedsRefresh() determines nothing needs to be done
// 2. t_now = t_refresh + 1 : r.RequeueAfter() determines that requeue should have happened 1 unit in the past
//
// In such a case, ctrl.Result{} with RequeueAfter < 0 would not cause a requeue, and we would hang until the next
// re-list for the controller.
func clampRequeue(requeue time.Duration) time.Duration {
	if requeue < 0 {
		return time.Second
	}
	return requeue
}

type pullBinding interface {
	*msiacrpullv1beta1.AcrPullBinding | *msiacrpullv1beta2.AcrPullBinding
	crclient.Object
}

// action captures the outcome of a reconciliation pass using static data, to aid in testing the reconciliation loop
type action[O pullBinding] struct {
	updatePullBinding       O
	noop                    O
	updatePullBindingStatus O

	createSecret *corev1.Secret
	updateSecret *corev1.Secret
	deleteSecret *corev1.Secret

	updateServiceAccount *corev1.ServiceAccount
}

func (a *action[O]) validate() {
	var present int
	if a.updatePullBinding != nil {
		present++
	}
	if a.noop != nil {
		present++
	}
	if a.updatePullBindingStatus != nil {
		present++
	}
	if a.createSecret != nil {
		present++
	}
	if a.updateSecret != nil {
		present++
	}
	if a.deleteSecret != nil {
		present++
	}
	if a.updateServiceAccount != nil {
		present++
	}
	if present > 1 {
		panic("programmer error: more than one action specified in reconciliation loop")
	}
}
