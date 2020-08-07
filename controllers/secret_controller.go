package controllers

import (
	"context"
	"time"

	v1 "k8s.io/api/core/v1"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/msi-acrpull/pkg/auth"
)

const (
	clientIDAnnotation = "msi-acrpull/clientID"
	acrAnnotation      = "msi-acrpull/acr"

	tokenRefreshBuffer          = time.Minute * 30
	defaultTokenRefreshDuration = time.Hour
)

// SecretReconciler reconciles a Secret object
type SecretReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;update;patch

func (r *SecretReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("secret", req.Name).WithValues("namespace", req.Namespace)

	var secret v1.Secret
	if err := r.Get(ctx, req.NamespacedName, &secret); err != nil {
		log.Error(err, "unable to fetch secret.")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if secret.Type != v1.SecretTypeDockerConfigJson {
		return ctrl.Result{}, nil
	}

	log.Info("Secret is a docker config json")

	clientID, ok := secret.Annotations[clientIDAnnotation]
	if !ok {
		log.Info("Secret does not have client id annotation, skip")
		return ctrl.Result{}, nil
	}

	acr, ok := secret.Annotations[acrAnnotation]
	if !ok {
		log.Info("Secret does not have acr annotation, skip")
		return ctrl.Result{}, nil
	}

	log.Info("Found specified client ID and ACR", "client_id", clientID, "acr", acr)

	acrAccessToken, err := auth.AcquireACRAccessToken(clientID, acr)
	if err != nil {
		log.Error(err, "Failed to get ACR access token")
		return ctrl.Result{}, err
	}

	dockerConfig, err := auth.CreateACRDockerCfg(acr, acrAccessToken)
	if err != nil {
		log.Error(err, "Failed to acquire acr docker config")
		return ctrl.Result{}, err
	}

	secret.Data[".dockerconfigjson"] = []byte(dockerConfig)

	if err := r.Update(ctx, &secret); err != nil {
		log.Error(err, "Failed to update secret")
		return ctrl.Result{}, err
	}

	// requeue the secret after refresh duration
	return ctrl.Result{
		Requeue:      true,
		RequeueAfter: getTokenRefreshDuration(acrAccessToken),
	}, nil
}

func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.Secret{}).
		Complete(r)
}

func getTokenRefreshDuration(accessToken auth.AccessToken) time.Duration {
	exp, err := accessToken.GetTokenExp()
	if err != nil {
		return defaultTokenRefreshDuration
	}

	refreshDuration := exp.Sub(time.Now().Add(tokenRefreshBuffer))
	if refreshDuration < 0 {
		return 0
	}

	return refreshDuration
}
