package controllers

import (
	"context"

	"github.com/Azure/msi-acrpull/auth"

	v1 "k8s.io/api/core/v1"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

	if secret.Type == v1.SecretTypeDockerConfigJson {
		log.Info("Secret is a docker config json")

		var clientID, acr string
		var ok bool
		if clientID, ok = secret.Annotations["msi-acrpull/clientID"]; !ok {
			log.Info("Secret does not have client id annotation, skip")
			return ctrl.Result{}, nil
		}

		if acr, ok = secret.Annotations["msi-acrpull/acr"]; !ok {
			log.Info("Secret does not have acr annotation, skip")
			return ctrl.Result{}, nil
		}

		log.Info("Found specified client ID and ACR", "client_id", clientID, "acr", acr)

		config, err := auth.AcquireACRDockerCfg(clientID, acr)
		if err != nil {
			log.Error(err, "Failed to acquire acr docker config")
			return ctrl.Result{}, err
		}

		secret.Data[".dockerconfigjson"] = []byte(config)

		if err := r.Update(ctx, &secret); err != nil {
			log.Error(err, "Failed to update secret")
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.Secret{}).
		Complete(r)
}
