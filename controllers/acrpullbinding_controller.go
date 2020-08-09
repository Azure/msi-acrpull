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

	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
	"github.com/Azure/msi-acrpull/pkg/auth"
)

const (
	ownerKey = ".metadata.controller"
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
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;update;patch

func (r *AcrPullBindingReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("acrpullbinding", req.NamespacedName)

	var acrBinding msiacrpullv1beta1.AcrPullBinding
	if err := r.Get(ctx, req.NamespacedName, &acrBinding); err != nil {
		log.Error(err, "unable to fetch acrPullBinding.")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	var pullSecrets v1.SecretList
	if err := r.List(ctx, &pullSecrets, client.InNamespace(req.Namespace), client.MatchingFields{ownerKey: req.Name}); err != nil {
		log.Error(err, "unable to list child secrets")
		return ctrl.Result{}, err
	}

	if len(pullSecrets.Items) > 1 {
		err := errors.New("more than 1 secret registered to this CRD")
		return ctrl.Result{
			Requeue: false,
		}, err
	}

	msiClientID := acrBinding.Spec.MsiClientID
	acrServer := acrBinding.Spec.AcrServer

	acrAccessToken, err := auth.AcquireACRAccessToken(msiClientID, acrServer)
	if err != nil {
		log.Error(err, "Failed to get ACR access token")
		return ctrl.Result{}, err
	}

	dockerConfig, err := auth.CreateACRDockerCfg(acrServer, acrAccessToken)
	if err != nil {
		log.Error(err, "Failed to acquire acr docker config")
		return ctrl.Result{}, err
	}

	// Create a new secret if one doesn't already exist
	if len(pullSecrets.Items) == 0 {
		pullSecret, err := newPullSecret(&acrBinding, dockerConfig, r.Scheme)
		if err != nil {
			log.Error(err, "Failed to create pull secret")
			return ctrl.Result{}, err
		}

		if err := r.Create(ctx, pullSecret); err != nil {
			log.Error(err, "Failed to create pull secret in cluster")
			return ctrl.Result{}, err
		}

		return ctrl.Result{
			Requeue:      true,
			RequeueAfter: getTokenRefreshDuration(acrAccessToken),
		}, nil
	}

	pullSecret := updatePullSecret(&pullSecrets.Items[0], dockerConfig)
	if err := r.Update(ctx, pullSecret); err != nil {
		log.Error(err, "Failed to update pull secret")
		return ctrl.Result{}, err
	}

	return ctrl.Result{
		Requeue:      true,
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
		Owns(&v1.Secret{}).
		Complete(r)
}

func updatePullSecret(pullSecret *v1.Secret, dockerConfig string) (*v1.Secret){
	pullSecret.Data[dockerConfigKey] = []byte(dockerConfig)
	return pullSecret
}

func newPullSecret(acrBinding *msiacrpullv1beta1.AcrPullBinding,
	dockerConfig string, scheme *runtime.Scheme) (*v1.Secret, error){

	pullSecret := &v1.Secret{
		Type: v1.SecretTypeDockerConfigJson,
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{},
			Annotations: map[string]string{},
			Name:      fmt.Sprintf("%s-msi-acrpull-secret", acrBinding.Name),
			Namespace: acrBinding.Namespace,
		},
		Data: map[string][]byte {
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

