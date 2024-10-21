package controller

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/big"
	"path"
	"slices"
	"strings"
	"time"

	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
	"github.com/Azure/msi-acrpull/pkg/authorizer"
	"github.com/Azure/msi-acrpull/pkg/authorizer/types"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
)

const (
	// ACRPullBindingLabel is a label on Secrets that holds the name of the ACRPullBinding for which the Secret holds a pull credential
	ACRPullBindingLabel = "acr.microsoft.com/binding"

	// tokenExpiryAnnotation is an annotation on Secrets that records the TTL for a pull credential expiry, in time.RFC3339 format
	tokenExpiryAnnotation = "acr.microsoft.com/token.expiry"
	// tokenRefreshAnnotation is an annotation on Secrets that records the time a pull credential was refreshed, in time.RFC3339 format
	tokenRefreshAnnotation = "acr.microsoft.com/token.refresh"
	// tokenInputsAnnotation is an annotation on Secrets that records the inputs that were used to create the pull credential, for change detection
	tokenInputsAnnotation = "acr.microsoft.com/token.inputs"

	ownerKey                  = ".metadata.controller"
	dockerConfigKey           = ".dockerconfigjson"
	msiAcrPullFinalizerName   = "msi-acrpull.microsoft.com"
	defaultServiceAccountName = "default"

	tokenRefreshBuffer = time.Minute * 30
)

// AcrPullBindingReconciler reconciles a AcrPullBinding object
type AcrPullBindingReconciler struct {
	client.Client
	Log                              logr.Logger
	Scheme                           *runtime.Scheme
	Auth                             authorizer.Interface
	DefaultManagedIdentityResourceID string
	DefaultManagedIdentityClientID   string
	DefaultACRServer                 string

	now func() time.Time
}

//+kubebuilder:rbac:groups=msi-acrpull.microsoft.com,resources=acrpullbindings,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=msi-acrpull.microsoft.com,resources=acrpullbindings/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=msi-acrpull.microsoft.com,resources=acrpullbindings/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=*
//+kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;update;patch

func (r *AcrPullBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("acrpullbinding", req.NamespacedName)

	acrBinding := &msiacrpullv1beta1.AcrPullBinding{}
	if err := r.Get(ctx, req.NamespacedName, acrBinding); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "unable to fetch acrPullBinding.")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	serviceAccount := &corev1.ServiceAccount{}
	if err := r.Get(ctx, k8stypes.NamespacedName{
		Namespace: req.Namespace,
		Name:      getServiceAccountName(acrBinding.Spec.ServiceAccountName),
	}, serviceAccount); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "failed to get service account")
			return ctrl.Result{}, err
		} else {
			serviceAccount = nil
		}
	}

	expectedPullSecretName := pullSecretName(acrBinding.Name)
	pullSecret := &corev1.Secret{}
	if err := r.Get(ctx, k8stypes.NamespacedName{
		Namespace: req.Namespace,
		Name:      expectedPullSecretName,
	}, pullSecret); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "failed to get pull secret")
			return ctrl.Result{}, err
		} else {
			pullSecret = nil
		}
	}

	var referencingServiceAccounts corev1.ServiceAccountList
	if err := r.List(ctx, &referencingServiceAccounts, client.InNamespace(acrBinding.GetNamespace()), client.MatchingFields{imagePullSecretsField: expectedPullSecretName}); err != nil {
		log.Error(err, "failed to fetch service accounts referencing pull secret")
		return ctrl.Result{}, err
	}

	action := r.reconcile(ctx, log, acrBinding, serviceAccount, pullSecret, referencingServiceAccounts.Items)

	return r.execute(ctx, action)
}

func (r *AcrPullBindingReconciler) reconcile(ctx context.Context, log logr.Logger, acrBinding *msiacrpullv1beta1.AcrPullBinding, serviceAccount *corev1.ServiceAccount, pullSecret *corev1.Secret, referencingServiceAccounts []corev1.ServiceAccount) *action {
	// examine DeletionTimestamp to determine if acr pull binding is under deletion
	if acrBinding.ObjectMeta.DeletionTimestamp.IsZero() {
		// the object is not being deleted, so if it does not have our finalizer,
		// then need to add the finalizer and update the object.
		if !slices.Contains(acrBinding.ObjectMeta.Finalizers, msiAcrPullFinalizerName) {
			updated := acrBinding.DeepCopy()
			updated.ObjectMeta.Finalizers = append(updated.ObjectMeta.Finalizers, msiAcrPullFinalizerName)
			log.Info("adding finalizer to pull binding")
			return &action{updatePullBinding: updated}
		}
	} else {
		// the object is being deleted, do cleanup as necessary
		return r.cleanUp(acrBinding, serviceAccount, pullSecret, log)
	}

	// if the user changed which service account should be bound to this credential, we need to
	// un-bind the credential from any service accounts it was bound to previously
	extraneousServiceAccounts := slices.DeleteFunc(referencingServiceAccounts, func(other corev1.ServiceAccount) bool {
		return serviceAccount != nil && other.Name == serviceAccount.Name
	})
	for _, extraneous := range extraneousServiceAccounts {
		updated := extraneous.DeepCopy()
		updated.ImagePullSecrets = slices.DeleteFunc(updated.ImagePullSecrets, func(reference corev1.LocalObjectReference) bool {
			return reference.Name == pullSecretName(acrBinding.ObjectMeta.Name)
		})
		if len(updated.ImagePullSecrets) != len(extraneous.ImagePullSecrets) {
			log.WithValues("serviceAccount", client.ObjectKeyFromObject(&extraneous).String()).Info("updating service account to remove image pull secret")
			return &action{updateServiceAccount: updated}
		}
	}

	if serviceAccount == nil {
		updated := acrBinding.DeepCopy()
		updated.Status.Error = fmt.Sprintf("service account %q not found", getServiceAccountName(acrBinding.Spec.ServiceAccountName))
		log.Info(updated.Status.Error)
		return &action{updatePullBindingStatus: updated}
	}

	msiClientID, msiResourceID, acrServer := specOrDefault(r, acrBinding.Spec)
	inputHash := base36sha224([]byte(msiClientID + msiResourceID + acrServer))
	if pullSecret == nil ||
		r.now().After(pullSecretExpiry(log, pullSecret).Add(-1*tokenRefreshBuffer)) ||
		pullSecret.Annotations[tokenInputsAnnotation] != inputHash {
		log.Info("generating new pull credential")
		var acrAccessToken types.AccessToken
		var err error

		if msiClientID != "" {
			acrAccessToken, err = r.Auth.AcquireACRAccessTokenWithClientID(ctx, log, msiClientID, acrServer)
		} else {
			acrAccessToken, err = r.Auth.AcquireACRAccessTokenWithResourceID(ctx, log, msiResourceID, acrServer)
		}
		if err != nil {
			updated := acrBinding.DeepCopy()
			updated.Status.Error = fmt.Sprintf("failed to retrieve ACR access token: %v", err)
			log.Info(updated.Status.Error)
			return &action{updatePullBindingStatus: updated}
		}

		dockerConfig := authorizer.CreateACRDockerCfg(acrServer, acrAccessToken)

		tokenExp, err := acrAccessToken.GetTokenExp()
		if err != nil {
			updated := acrBinding.DeepCopy()
			updated.Status.Error = fmt.Sprintf("failed to retrieve ACR access token expiry: %v", err)
			log.Info(updated.Status.Error)
			return &action{updatePullBindingStatus: updated}
		}
		newSecret := newPullSecret(acrBinding, dockerConfig, r.Scheme, tokenExp, r.now, inputHash)
		log = log.WithValues("secret", client.ObjectKeyFromObject(newSecret).String())
		if pullSecret == nil {
			log.Info("creating pull credential secret")
			return &action{createSecret: newSecret}
		} else {
			log.Info("updating pull credential secret")
			return &action{updateSecret: newSecret}
		}
	}

	if !slices.ContainsFunc(serviceAccount.ImagePullSecrets, func(reference corev1.LocalObjectReference) bool {
		return reference.Name == pullSecret.Name
	}) {
		updated := serviceAccount.DeepCopy()
		updated.ImagePullSecrets = append(updated.ImagePullSecrets, corev1.LocalObjectReference{
			Name: pullSecret.Name,
		})
		log.WithValues("serviceAccount", client.ObjectKeyFromObject(serviceAccount).String()).Info("updating service account to add image pull secret")
		return &action{updateServiceAccount: updated}
	}

	return r.setSuccessStatus(log, acrBinding, pullSecret)
}

func (r *AcrPullBindingReconciler) execute(ctx context.Context, action *action) (ctrl.Result, error) {
	if action == nil {
		return ctrl.Result{}, nil
	}
	action.validate()
	if action.updatePullBinding != nil {
		return ctrl.Result{}, r.Update(ctx, action.updatePullBinding)
	} else if action.updatePullBindingStatus != nil {
		var requeueAfter time.Duration
		if action.updatePullBindingStatus.Status.TokenExpirationTime != nil {
			requeueAfter = action.updatePullBindingStatus.Status.TokenExpirationTime.Time.Sub(r.now().Add(tokenRefreshBuffer))
		}
		return ctrl.Result{RequeueAfter: requeueAfter}, r.Status().Update(ctx, action.updatePullBindingStatus)
	} else if action.createSecret != nil {
		return ctrl.Result{}, r.Create(ctx, action.createSecret)
	} else if action.updateSecret != nil {
		return ctrl.Result{}, r.Update(ctx, action.updateSecret)
	} else if action.deleteSecret != nil {
		return ctrl.Result{}, r.Delete(ctx, action.deleteSecret)
	} else if action.updateServiceAccount != nil {
		return ctrl.Result{}, r.Update(ctx, action.updateServiceAccount)
	}
	return ctrl.Result{}, nil
}

// action captures the outcome of a reconciliation pass using static data, to aid in testing the reconciliation loop
type action struct {
	updatePullBinding       *msiacrpullv1beta1.AcrPullBinding
	updatePullBindingStatus *msiacrpullv1beta1.AcrPullBinding

	createSecret *corev1.Secret
	updateSecret *corev1.Secret
	deleteSecret *corev1.Secret

	updateServiceAccount *corev1.ServiceAccount
}

func (a *action) validate() {
	var present int
	if a.updatePullBinding != nil {
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

func specOrDefault(r *AcrPullBindingReconciler, spec msiacrpullv1beta1.AcrPullBindingSpec) (string, string, string) {
	msiClientID := spec.ManagedIdentityClientID
	msiResourceID := path.Clean(spec.ManagedIdentityResourceID)
	acrServer := spec.AcrServer
	if msiClientID == "" {
		msiClientID = r.DefaultManagedIdentityClientID
	}
	if msiResourceID == "." {
		msiResourceID = r.DefaultManagedIdentityResourceID
	}
	if acrServer == "" {
		acrServer = r.DefaultACRServer
	}
	return msiClientID, msiResourceID, acrServer
}

// pullSecretExpiry determines when a pull credential stored in a Secret expires
func pullSecretExpiry(log logr.Logger, secret *corev1.Secret) time.Time {
	if secret == nil {
		return time.Time{}
	}

	formattedExpiry, annotated := secret.Annotations[tokenExpiryAnnotation]
	if !annotated {
		return time.Time{}
	}

	expiry, err := time.Parse(time.RFC3339, formattedExpiry)
	if err != nil {
		// we should never get into this state unless some other actor corrupts our annotation,
		// so we can consider this token expired and re-generate it to get back to a good state
		log.WithValues("secret", client.ObjectKeyFromObject(secret).String()).Error(err, "unexpected error parsing expiry annotation on secret")
		return time.Time{}
	}

	return expiry
}

func (r *AcrPullBindingReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	if r.now == nil {
		r.now = time.Now
	}
	if err := mgr.GetFieldIndexer().IndexField(ctx, &msiacrpullv1beta1.AcrPullBinding{}, serviceAccountField, indexPullBindingByServiceAccount); err != nil {
		return err
	}
	if err := mgr.GetFieldIndexer().IndexField(ctx, &corev1.ServiceAccount{}, imagePullSecretsField, func(object client.Object) []string {
		serviceAccount, ok := object.(*corev1.ServiceAccount)
		if !ok {
			return nil
		}

		var imagePullSecrets []string
		for _, secretRef := range serviceAccount.ImagePullSecrets {
			if strings.HasPrefix(secretRef.Name, pullSecretNamePrefix) {
				imagePullSecrets = append(imagePullSecrets, secretRef.Name)
			}
		}

		return imagePullSecrets
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&msiacrpullv1beta1.AcrPullBinding{}).
		Named("acr-pull-binding").
		Owns(&corev1.Secret{}).
		Watches(&corev1.ServiceAccount{}, handler.EnqueueRequestsFromMapFunc(enqueuePullBindingsForServiceAccount(mgr))).
		Complete(r)
}

func (r *AcrPullBindingReconciler) cleanUp(acrBinding *msiacrpullv1beta1.AcrPullBinding,
	serviceAccount *corev1.ServiceAccount, pullSecret *corev1.Secret, log logr.Logger) *action {
	if slices.Contains(acrBinding.ObjectMeta.Finalizers, msiAcrPullFinalizerName) {
		// our finalizer is present, so need to clean up ImagePullSecret reference
		if serviceAccount == nil {
			log.Info("Service account is not found. Continue removing finalizer")
		} else {
			updated := serviceAccount.DeepCopy()
			updated.ImagePullSecrets = slices.DeleteFunc(updated.ImagePullSecrets, func(reference corev1.LocalObjectReference) bool {
				return reference.Name == pullSecretName(acrBinding.ObjectMeta.Name)
			})
			if len(updated.ImagePullSecrets) != len(serviceAccount.ImagePullSecrets) {
				log.WithValues("serviceAccount", client.ObjectKeyFromObject(serviceAccount).String()).Info("updating service account to remove image pull secret")
				return &action{updateServiceAccount: updated}
			}
		}

		// remove the secret
		if pullSecret != nil {
			log.WithValues("secret", client.ObjectKeyFromObject(pullSecret).String()).Info("cleaning up pull credential")
			return &action{deleteSecret: pullSecret}
		}

		// remove our finalizer from the list and update it.
		updated := acrBinding.DeepCopy()
		updated.ObjectMeta.Finalizers = slices.DeleteFunc(updated.ObjectMeta.Finalizers, func(s string) bool {
			return s == msiAcrPullFinalizerName
		})
		log.Info("removing finalizer from pull binding")
		return &action{updatePullBinding: updated}
	}
	log.Info("no finalizer present, nothing to do")
	return nil
}

func (r *AcrPullBindingReconciler) setSuccessStatus(log logr.Logger, acrBinding *msiacrpullv1beta1.AcrPullBinding, pullSecret *corev1.Secret) *action {
	log = log.WithValues("secret", client.ObjectKeyFromObject(pullSecret).String())

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

	if acrBinding.Status.TokenExpirationTime == nil || !acrBinding.Status.TokenExpirationTime.Equal(&metav1.Time{Time: expiry}) ||
		acrBinding.Status.LastTokenRefreshTime == nil || !acrBinding.Status.LastTokenRefreshTime.Equal(&metav1.Time{Time: refresh}) {
		updated := acrBinding.DeepCopy()
		updated.Status.TokenExpirationTime = &metav1.Time{Time: expiry}
		updated.Status.LastTokenRefreshTime = &metav1.Time{Time: refresh}
		log.Info("updating pull binding to reflect expiry and refresh time from secret")
		return &action{updatePullBindingStatus: updated}
	}
	return nil
}

func getServiceAccountName(userSpecifiedName string) string {
	if userSpecifiedName != "" {
		return userSpecifiedName
	}
	return defaultServiceAccountName
}

func base36sha224(input []byte) string {
	// base36(sha224(value)) produces a useful, deterministic value that fits the requirements to be
	// a Kubernetes object name (honoring length requirement, is a valid DNS subdomain, etc)
	hash := sha256.Sum224(input)
	var i big.Int
	i.SetBytes(hash[:])
	return i.Text(36)
}

const (
	maxNameLength        = 64 /* longest object name */ - 10 /* length of static content */ - 10 /* length of hash */
	pullSecretNamePrefix = "acr-pull-"
)

func pullSecretName(acrBindingName string) string {
	suffix := acrBindingName
	if len(suffix) > maxNameLength {
		suffix = suffix[:maxNameLength]
	}
	suffix = strings.TrimSuffix(suffix, ".") // trailing domain label separators can't be followed by '-'
	return pullSecretNamePrefix + suffix + "-" + base36sha224([]byte(acrBindingName))[:10]
}

func legacySecretName(acrBindingName string) string {
	return fmt.Sprintf("%s-msi-acrpull-secret", acrBindingName)
}

func newPullSecret(acrBinding *msiacrpullv1beta1.AcrPullBinding,
	dockerConfig string, scheme *runtime.Scheme, expiry time.Time, now func() time.Time, inputHash string) *corev1.Secret {

	pullSecret := &corev1.Secret{
		Type: corev1.SecretTypeDockerConfigJson,
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				ACRPullBindingLabel: acrBinding.ObjectMeta.Name,
			},
			Annotations: map[string]string{
				tokenExpiryAnnotation:  expiry.Format(time.RFC3339),
				tokenRefreshAnnotation: now().Format(time.RFC3339),
				tokenInputsAnnotation:  inputHash,
			},
			Name:      pullSecretName(acrBinding.Name),
			Namespace: acrBinding.Namespace,
		},
		Data: map[string][]byte{
			dockerConfigKey: []byte(dockerConfig),
		},
	}

	if err := ctrl.SetControllerReference(acrBinding, pullSecret, scheme); err != nil {
		// ctrl.SetControllerReference can only error if the object already has an owner, and we're
		// creating this object from scratch so we know it cannot ever error, so handle this inline
		panic(fmt.Sprintf("programmer error: cannot set controller reference: %v", err))
	}

	return pullSecret
}
