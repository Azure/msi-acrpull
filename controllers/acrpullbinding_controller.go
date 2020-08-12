package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
	"github.com/Azure/msi-acrpull/pkg/authorizer"
)

const (
	ownerKey        = ".metadata.controller"
	dockerConfigKey = ".dockerconfigjson"

	tokenRefreshBuffer = time.Minute * 30
)

// AcrPullBindingReconciler reconciles a AcrPullBinding object
type AcrPullBindingReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=msi-acrpull.microsoft.com,resources=acrpullbindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=msi-acrpull.microsoft.com,resources=acrpullbindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=*

func (r *AcrPullBindingReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("acrpullbinding", req.NamespacedName)

	var acrBinding msiacrpullv1beta1.AcrPullBinding
	if err := r.Get(ctx, req.NamespacedName, &acrBinding); err != nil {
		log.Error(err, "unable to fetch acrPullBinding.")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	msiClientID := acrBinding.Spec.ManagedIdentityClientID
	msiResourceID := acrBinding.Spec.ManagedIdentityResourceID
	acrServer := acrBinding.Spec.AcrServer

	var acrAccessToken authorizer.AccessToken
	var err error

	az := authorizer.NewAuthorizer()

	if msiClientID != "" {
		acrAccessToken, err = az.AcquireACRAccessTokenWithClientID(msiClientID, acrServer)
	} else {
		acrAccessToken, err = az.AcquireACRAccessTokenWithResourceID(msiResourceID, acrServer)
	}
	if err != nil {
		log.Error(err, "Failed to get ACR access token")
		if err := r.setErrStatus(ctx, err, &acrBinding); err != nil {
			log.Error(err, "Failed to update error status")
		}

		return ctrl.Result{}, err
	}

	dockerConfig := authorizer.CreateACRDockerCfg(acrServer, acrAccessToken)

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

func (r *AcrPullBindingReconciler) setSuccessStatus(ctx context.Context, acrBinding *msiacrpullv1beta1.AcrPullBinding, accessToken authorizer.AccessToken) error {
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

func getTokenRefreshDuration(accessToken authorizer.AccessToken) time.Duration {
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
