package controllers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
	"github.com/Azure/msi-acrpull/pkg/auth"
)

const (
	ownerKey                = ".metadata.controller"
	dockerConfigKey         = ".dockerconfigjson"
	msiAcrPullFinalizerName = "msi-acrpull.microsoft.com"

	tokenRefreshBuffer = time.Minute * 30
)

var serviceAccountLocks = make(map[types.NamespacedName]*sync.Mutex)

// AcrPullBindingReconciler reconciles a AcrPullBinding object
type AcrPullBindingReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=msi-acrpull.microsoft.com,resources=acrpullbindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=msi-acrpull.microsoft.com,resources=acrpullbindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=*
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;update;patch

func (r *AcrPullBindingReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("acrpullbinding", req.NamespacedName)

	var acrBinding msiacrpullv1beta1.AcrPullBinding
	if err := r.Get(ctx, req.NamespacedName, &acrBinding); err != nil {
		log.Info("Unable to fetch acrPullBinding.")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// examine DeletionTimestamp to determine if object is under deletion
	if acrBinding.ObjectMeta.DeletionTimestamp.IsZero() {
		// The object is not being deleted, so if it does not have our finalizer,
		// then lets add the finalizer and update the object. This is equivalent
		// registering our finalizer.
		if !containsString(acrBinding.ObjectMeta.Finalizers, msiAcrPullFinalizerName) {
			log.Info(fmt.Sprintf("Adding acr pull binding finalizer: %v", acrBinding.ObjectMeta.Finalizers))
			acrBinding.ObjectMeta.Finalizers = append(acrBinding.ObjectMeta.Finalizers, msiAcrPullFinalizerName)
			if err := r.Update(ctx, &acrBinding); err != nil {
				log.Error(err, fmt.Sprintf("Failed to append acr pull binding finalizer %s", msiAcrPullFinalizerName))
				return ctrl.Result{}, err
			}
		}
	} else {
		// The object is being deleted
		if containsString(acrBinding.ObjectMeta.Finalizers, msiAcrPullFinalizerName) {
			// our finalizer is present, so need to clean up ImagePullSecret reference
			var serviceAccount v1.ServiceAccount
			saNamespacedName := types.NamespacedName{
				Namespace: req.Namespace,
				Name:      "default",
			}
			if err := r.Get(ctx, saNamespacedName, &serviceAccount); err != nil {
				log.Error(err, "Failed to get default service account")
				return ctrl.Result{}, err
			}
			pullSecretName := getPullSecretName(acrBinding.Name)
			serviceAccount.ImagePullSecrets = removeImagePullSecretRef(serviceAccount.ImagePullSecrets, pullSecretName)
			if err := r.Update(ctx, &serviceAccount); err != nil {
				log.Error(err, fmt.Sprintf("Failed to remove image pull secret reference %s from default service account", pullSecretName))
				return ctrl.Result{}, err
			}

			// remove our finalizer from the list and update it.
			acrBinding.ObjectMeta.Finalizers = removeString(acrBinding.ObjectMeta.Finalizers, msiAcrPullFinalizerName)
			log.Info(fmt.Sprintf("Removing acr pull binding finalizer: %v", acrBinding.ObjectMeta.Finalizers))
			if err := r.Update(ctx, &acrBinding); err != nil {
				log.Error(err, fmt.Sprintf("Failed to remove acr pull binding finalizer %s", msiAcrPullFinalizerName))
				return ctrl.Result{}, err
			}
		}

		// Stop reconciliation as the item is being deleted
		return ctrl.Result{}, nil
	}

	msiClientID := acrBinding.Spec.ManagedIdentityClientID
	acrServer := acrBinding.Spec.AcrServer

	acrAccessToken, err := auth.AcquireACRAccessToken(msiClientID, acrServer)
	if err != nil {
		log.Error(err, "Failed to get ACR access token")
		if err := r.setErrStatus(ctx, err, &acrBinding); err != nil {
			log.Error(err, "Failed to update error status")
		}

		return ctrl.Result{}, err
	}

	dockerConfig := auth.CreateACRDockerCfg(acrServer, acrAccessToken)

	var pullSecrets v1.SecretList
	if err := r.List(ctx, &pullSecrets, client.InNamespace(req.Namespace), client.MatchingFields{ownerKey: req.Name}); err != nil {
		log.Error(err, "unable to list child secrets")
		return ctrl.Result{}, err
	}
	pullSecret := getPullSecret(&acrBinding, pullSecrets.Items, log)

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

	var serviceAccount v1.ServiceAccount
	saNamespacedName := types.NamespacedName{
		Namespace: req.Namespace,
		Name:      "default",
	}
	if lock, ok := serviceAccountLocks[saNamespacedName]; ok {
		lock.Lock()
		defer lock.Unlock()
	} else {
		newLock := &sync.Mutex{}
		newLock.Lock()
		defer newLock.Unlock()
		serviceAccountLocks[saNamespacedName] = newLock
	}
	if err := r.Get(ctx, saNamespacedName, &serviceAccount); err != nil {
		log.Error(err, "Failed to get default service account")
		return ctrl.Result{}, err
	}
	if pullSecret != nil && !imagePullSecretRefExist(serviceAccount.ImagePullSecrets, pullSecret.Name) {
		log.Info("Updating default service account")

		secretNames := ""
		for _, secret := range serviceAccount.ImagePullSecrets {
			secretNames += secret.Name + " "
		}
		log.Info(fmt.Sprintf("Service account current pullSecrets: %v", secretNames))

		appendImagePullSecretRef(&serviceAccount, pullSecret.Name)
		if err := r.Update(ctx, &serviceAccount); err != nil {
			log.Error(err, fmt.Sprintf("Failed to append image pull secret reference %s to default service account", pullSecret.Name))
			return ctrl.Result{}, err
		}
	}

	if err := r.setSuccessStatus(ctx, &acrBinding, acrAccessToken); err != nil {
		log.Error(err, "Failed to update acr binding status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{
		RequeueAfter: getTokenRefreshDuration(acrAccessToken),
	}, nil
}

func (r *AcrPullBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(&v1.Secret{}, ownerKey, func(rawObj runtime.Object) []string {
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

func (r *AcrPullBindingReconciler) setSuccessStatus(ctx context.Context, acrBinding *msiacrpullv1beta1.AcrPullBinding, accessToken auth.AccessToken) error {
	tokenExp, err := accessToken.GetTokenExp()
	if err != nil {
		return err
	}

	acrBinding.Status = msiacrpullv1beta1.AcrPullBindingStatus{
		TokenExpirationTime:  &metav1.Time{Time: tokenExp},
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

func imagePullSecretRefExist(imagePullSecretRefs []v1.LocalObjectReference, secretName string) bool {
	if imagePullSecretRefs == nil {
		return false
	}
	for _, secretRef := range imagePullSecretRefs {
		if secretRef.Name == secretName {
			return true
		}
	}
	return false
}

func removeImagePullSecretRef(imagePullSecretRefs []v1.LocalObjectReference, secretName string) []v1.LocalObjectReference {
	var result []v1.LocalObjectReference
	for _, secretRef := range imagePullSecretRefs {
		if secretRef.Name == secretName {
			continue
		}
		result = append(result, secretRef)
	}
	return result
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func removeString(slice []string, s string) []string {
	var result []string
	for _, item := range slice {
		if item == s {
			continue
		}
		result = append(result, item)
	}
	return result
}

func getPullSecretName(acrBindingName string) string {
	return fmt.Sprintf("%s-msi-acrpull-secret", acrBindingName)
}

func getPullSecret(acrBinding *msiacrpullv1beta1.AcrPullBinding, pullSecrets []v1.Secret, log logr.Logger) *v1.Secret {
	if pullSecrets == nil {
		return nil
	}

	secretNames := ""
	for _, secret := range pullSecrets {
		secretNames += secret.Name + " "
	}
	log.Info(fmt.Sprintf("pullSecrets: %v", secretNames))
	log.Info(fmt.Sprintf("acr binding: %s", acrBinding.Name))
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

func getTokenRefreshDuration(accessToken auth.AccessToken) time.Duration {
	exp, err := accessToken.GetTokenExp()
	if err != nil {
		return 0
	}

	refreshDuration := exp.Sub(time.Now().Add(tokenRefreshBuffer))
	if refreshDuration < 0 {
		return 0
	}

	return refreshDuration
}
