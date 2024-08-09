package controller

import (
	"context"
	"fmt"
	"path"
	"slices"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
	"github.com/Azure/msi-acrpull/pkg/authorizer"
)

const (
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
}

//+kubebuilder:rbac:groups=msi-acrpull.microsoft.com,resources=acrpullbindings,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=msi-acrpull.microsoft.com,resources=acrpullbindings/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=msi-acrpull.microsoft.com,resources=acrpullbindings/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=*
//+kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;update;patch

func (r *AcrPullBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("acrpullbinding", req.NamespacedName)

	var acrBinding msiacrpullv1beta1.AcrPullBinding
	if err := r.Get(ctx, req.NamespacedName, &acrBinding); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "unable to fetch acrPullBinding.")
			return ctrl.Result{}, err
		}
		log.Info("AcrPullBinding is not found. Ignore because this is expected to happen when it is being deleted.")
		return ctrl.Result{}, nil
	}

	serviceAccountName := getServiceAccountName(acrBinding.Spec.ServiceAccountName)

	// examine DeletionTimestamp to determine if acr pull binding is under deletion
	if acrBinding.ObjectMeta.DeletionTimestamp.IsZero() {
		// the object is not being deleted, so if it does not have our finalizer,
		// then need to add the finalizer and update the object.
		if err := r.addFinalizer(ctx, &acrBinding, log); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		// the object is being deleted
		if err := r.removeFinalizer(ctx, &acrBinding, req, serviceAccountName, log); err != nil {
			return ctrl.Result{}, err
		}

		// stop reconciliation as the item is being deleted
		return ctrl.Result{}, nil
	}

	msiClientID, msiResourceID, acrServer := specOrDefault(r, acrBinding.Spec)
	var acrAccessToken azcore.AccessToken
	var err error

	if msiClientID != "" {
		acrAccessToken, err = r.Auth.AcquireACRAccessTokenWithClientID(ctx, msiClientID, acrServer)
	} else {
		acrAccessToken, err = r.Auth.AcquireACRAccessTokenWithResourceID(ctx, msiResourceID, acrServer)
	}
	if err != nil {
		log.Error(err, "Failed to get ACR access token")
		if err := r.setErrStatus(ctx, err, &acrBinding); err != nil {
			log.Error(err, "Failed to update error status")
		}

		return ctrl.Result{}, err
	}

	dockerConfig, err := authorizer.CreateACRDockerCfg(acrServer, acrAccessToken)
	if err != nil {
		log.Error(err, "unable to create DockerConfig")
		return ctrl.Result{}, err
	}

	var pullSecrets v1.SecretList
	if err := r.List(ctx, &pullSecrets, client.InNamespace(req.Namespace), client.MatchingFields{ownerKey: req.Name}); err != nil {
		log.Error(err, "unable to list child secrets")
		return ctrl.Result{}, err
	}
	pullSecret := getPullSecret(&acrBinding, pullSecrets.Items)

	// Create a new secret if one doesn't already exist
	if pullSecret == nil {
		log.Info("Creating new pull secret")

		pullSecret, err := newBasePullSecret(&acrBinding, dockerConfig, r.Scheme)
		if err != nil {
			log.Error(err, "Failed to construct pull secret")
			return ctrl.Result{}, err
		}

		if err := r.Create(ctx, pullSecret); err != nil {
			log.Error(err, "Failed to create pull secret in cluster")
			return ctrl.Result{}, err
		}
	} else {
		log.Info("Updating existing pull secret")

		pullSecret := updatePullSecret(&pullSecrets.Items[0], dockerConfig)
		if err := r.Update(ctx, pullSecret); err != nil {
			log.Error(err, "Failed to update pull secret")
			return ctrl.Result{}, err
		}
	}

	// Associate the image pull secret with the default service account of the namespace
	if err := r.updateServiceAccount(ctx, &acrBinding, req, serviceAccountName, log); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.setSuccessStatus(ctx, &acrBinding, acrAccessToken); err != nil {
		log.Error(err, "Failed to update acr binding status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{
		RequeueAfter: getTokenRefreshDuration(acrAccessToken),
	}, nil
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

func (r *AcrPullBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	ctx := context.Background()
	if err := mgr.GetFieldIndexer().IndexField(ctx, &v1.Secret{}, ownerKey, func(rawObj client.Object) []string {
		secret := rawObj.(*v1.Secret)
		owner := metav1.GetControllerOf(secret)
		if owner == nil {
			return nil
		}

		if owner.APIVersion != msiacrpullv1beta1.GroupVersion.String() || owner.Kind != "AcrPullBinding" {
			return nil
		}

		return []string{owner.Name}
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&msiacrpullv1beta1.AcrPullBinding{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}). // Needed to not enter reconcile loop on status update
		Owns(&v1.Secret{}).
		Complete(r)
}

func (r *AcrPullBindingReconciler) addFinalizer(ctx context.Context, acrBinding *msiacrpullv1beta1.AcrPullBinding, log logr.Logger) error {
	if !slices.Contains(acrBinding.ObjectMeta.Finalizers, msiAcrPullFinalizerName) {
		acrBinding.ObjectMeta.Finalizers = append(acrBinding.ObjectMeta.Finalizers, msiAcrPullFinalizerName)
		if err := r.Update(ctx, acrBinding); err != nil {
			log.Error(err, "Failed to append acr pull binding finalizer", "finalizerName", msiAcrPullFinalizerName)
			return err
		}
	}
	return nil
}

func (r *AcrPullBindingReconciler) removeFinalizer(ctx context.Context, acrBinding *msiacrpullv1beta1.AcrPullBinding,
	req ctrl.Request, serviceAccountName string, log logr.Logger) error {
	if slices.Contains(acrBinding.ObjectMeta.Finalizers, msiAcrPullFinalizerName) {
		// our finalizer is present, so need to clean up ImagePullSecret reference
		var serviceAccount v1.ServiceAccount
		saNamespacedName := k8stypes.NamespacedName{
			Namespace: req.Namespace,
			Name:      serviceAccountName,
		}
		if err := r.Get(ctx, saNamespacedName, &serviceAccount); err != nil {
			if !apierrors.IsNotFound(err) {
				log.Error(err, "Failed to get service account")
				return err
			}
			log.Info("Service account is not found. Continue removing finalizer", "serviceAccountName", saNamespacedName.Name)
		} else {
			pullSecretName := getPullSecretName(acrBinding.Name)
			serviceAccount.ImagePullSecrets = slices.DeleteFunc(serviceAccount.ImagePullSecrets, func(reference v1.LocalObjectReference) bool {
				return reference.Name == pullSecretName
			})
			if err := r.Update(ctx, &serviceAccount); err != nil {
				log.Error(err, "Failed to remove image pull secret reference from default service account", "pullSecretName", pullSecretName)
				return err
			}
		}

		// remove our finalizer from the list and update it.
		acrBinding.ObjectMeta.Finalizers = slices.DeleteFunc(acrBinding.ObjectMeta.Finalizers, func(s string) bool {
			return s == msiAcrPullFinalizerName
		})
		if err := r.Update(ctx, acrBinding); err != nil {
			log.Error(err, "Failed to remove acr pull binding finalizer", "finalizerName", msiAcrPullFinalizerName)
			return err
		}
	}
	return nil
}

func (r *AcrPullBindingReconciler) updateServiceAccount(ctx context.Context, acrBinding *msiacrpullv1beta1.AcrPullBinding,
	req ctrl.Request, serviceAccountName string, log logr.Logger) error {
	var serviceAccount v1.ServiceAccount
	saNamespacedName := k8stypes.NamespacedName{
		Namespace: req.Namespace,
		Name:      serviceAccountName,
	}
	if err := r.Get(ctx, saNamespacedName, &serviceAccount); err != nil {
		log.Error(err, "Failed to get service account")
		return err
	}
	pullSecretName := getPullSecretName(acrBinding.Name)
	if !slices.ContainsFunc(serviceAccount.ImagePullSecrets, func(reference v1.LocalObjectReference) bool {
		return reference.Name == pullSecretName
	}) {
		log.Info("Updating default service account")
		appendImagePullSecretRef(&serviceAccount, pullSecretName)
		if err := r.Update(ctx, &serviceAccount); err != nil {
			log.Error(err, "Failed to append image pull secret reference to default service account", "pullSecretName", pullSecretName)
			return err
		}
	}
	return nil
}

func (r *AcrPullBindingReconciler) setSuccessStatus(ctx context.Context, acrBinding *msiacrpullv1beta1.AcrPullBinding, accessToken azcore.AccessToken) error {
	acrBinding.Status = msiacrpullv1beta1.AcrPullBindingStatus{
		TokenExpirationTime:  &metav1.Time{Time: accessToken.ExpiresOn},
		LastTokenRefreshTime: &metav1.Time{Time: time.Now().UTC()},
	}

	if err := r.Status().Update(ctx, acrBinding); err != nil {
		return err
	}

	return nil
}

func (r *AcrPullBindingReconciler) setErrStatus(ctx context.Context, err error, acrBinding *msiacrpullv1beta1.AcrPullBinding) error {
	acrBinding.Status.Error = err.Error()
	if err := r.Status().Update(ctx, acrBinding); err != nil {
		return err
	}

	return nil
}

func updatePullSecret(pullSecret *v1.Secret, dockerConfig string) *v1.Secret {
	pullSecret.Data[dockerConfigKey] = []byte(dockerConfig)
	return pullSecret
}

func appendImagePullSecretRef(serviceAccount *v1.ServiceAccount, secretName string) {
	secretReference := &v1.LocalObjectReference{
		Name: secretName,
	}
	serviceAccount.ImagePullSecrets = append(serviceAccount.ImagePullSecrets, *secretReference)
}

func getServiceAccountName(userSpecifiedName string) string {
	if userSpecifiedName != "" {
		return userSpecifiedName
	}
	return defaultServiceAccountName
}

func getPullSecretName(acrBindingName string) string {
	return fmt.Sprintf("%s-msi-acrpull-secret", acrBindingName)
}

func getPullSecret(acrBinding *msiacrpullv1beta1.AcrPullBinding, pullSecrets []v1.Secret) *v1.Secret {
	if pullSecrets == nil {
		return nil
	}

	pullSecretName := getPullSecretName(acrBinding.Name)

	for idx, secret := range pullSecrets {
		if secret.Name == pullSecretName {
			return &pullSecrets[idx]
		}
	}

	return nil
}

func newBasePullSecret(acrBinding *msiacrpullv1beta1.AcrPullBinding,
	dockerConfig string, scheme *runtime.Scheme) (*v1.Secret, error) {

	pullSecret := &v1.Secret{
		Type: v1.SecretTypeDockerConfigJson,
		ObjectMeta: metav1.ObjectMeta{
			Labels:      map[string]string{},
			Annotations: map[string]string{},
			Name:        getPullSecretName(acrBinding.Name),
			Namespace:   acrBinding.Namespace,
		},
		Data: map[string][]byte{
			dockerConfigKey: []byte(dockerConfig),
		},
	}

	if err := ctrl.SetControllerReference(acrBinding, pullSecret, scheme); err != nil {
		return nil, errors.Wrap(err, "failed to create Acr ImagePullSecret")
	}

	return pullSecret, nil
}

func getTokenRefreshDuration(accessToken azcore.AccessToken) time.Duration {
	refreshDuration := accessToken.ExpiresOn.Sub(time.Now().Add(tokenRefreshBuffer))
	if refreshDuration < 0 {
		return 0
	}

	return refreshDuration
}
