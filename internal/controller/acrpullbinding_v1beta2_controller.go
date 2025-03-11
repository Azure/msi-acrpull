package controller

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azworkloadidentity "github.com/Azure/azure-workload-identity/pkg/webhook"
	msiacrpullv1beta2 "github.com/Azure/msi-acrpull/api/v1beta2"
	"github.com/Azure/msi-acrpull/pkg/authorizer"
	"github.com/go-logr/logr"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type CoreOpts struct {
	Client crclient.Client
	Logger logr.Logger
	Scheme *runtime.Scheme

	now func() time.Time
}

type ServiceAccountTokenMinter func(ctx context.Context, serviceAccountNamespace, serviceAccountName string) (*authenticationv1.TokenRequest, error)
type armTokenFetcher func(ctx context.Context, spec msiacrpullv1beta2.AcrPullBindingSpec, tenantId, clientId, serviceAccountToken string) (azcore.AccessToken, error)
type armAcrTokenExchanger func(ctx context.Context, armToken azcore.AccessToken, spec msiacrpullv1beta2.AcrConfiguration) (azcore.AccessToken, error)

// V1beta2ReconcilerOpts configures the inputs for reconciling v1beta2 pull bindings
type V1beta2ReconcilerOpts struct {
	CoreOpts

	TTLRotationFraction         float64
	ServiceAccountClient        corev1client.ServiceAccountsGetter
	ServiceAccountTokenAudience string

	// exposed here to allow unit tests to over-write them
	mintToken                   ServiceAccountTokenMinter
	fetchArmToken               armTokenFetcher
	exchangeArmTokenForAcrToken armAcrTokenExchanger
}

func NewV1beta2Reconciler(opts *V1beta2ReconcilerOpts) *PullBindingReconciler {
	if opts.now == nil {
		opts.now = time.Now
	}
	if opts.fetchArmToken == nil {
		opts.fetchArmToken = authorizer.ARMTokenForBinding
	}
	if opts.exchangeArmTokenForAcrToken == nil {
		opts.exchangeArmTokenForAcrToken = authorizer.ExchangeACRAccessTokenForSpec
	}
	if opts.mintToken == nil {
		opts.mintToken = func(ctx context.Context, serviceAccountNamespace, serviceAccountName string) (*authenticationv1.TokenRequest, error) {
			return opts.ServiceAccountClient.ServiceAccounts(serviceAccountNamespace).CreateToken(ctx, serviceAccountName, &authenticationv1.TokenRequest{
				Spec: authenticationv1.TokenRequestSpec{
					Audiences: []string{opts.ServiceAccountTokenAudience},
				},
			}, metav1.CreateOptions{})
		}
	}

	return &PullBindingReconciler{
		genericReconciler: &genericReconciler[*msiacrpullv1beta2.AcrPullBinding]{
			Client: opts.Client,
			Logger: opts.Logger,
			Scheme: opts.Scheme,
			NewBinding: func() *msiacrpullv1beta2.AcrPullBinding {
				return &msiacrpullv1beta2.AcrPullBinding{}
			},
			AddFinalizer: func(binding *msiacrpullv1beta2.AcrPullBinding, finalizer string) *msiacrpullv1beta2.AcrPullBinding {
				updated := binding.DeepCopy()
				updated.ObjectMeta.Finalizers = append(updated.ObjectMeta.Finalizers, finalizer)
				return updated
			},
			RemoveFinalizer: func(binding *msiacrpullv1beta2.AcrPullBinding, finalizer string) *msiacrpullv1beta2.AcrPullBinding {
				updated := binding.DeepCopy()
				updated.ObjectMeta.Finalizers = slices.DeleteFunc(updated.ObjectMeta.Finalizers, func(s string) bool {
					return s == finalizer
				})
				return updated
			},
			GetServiceAccountName: func(binding *msiacrpullv1beta2.AcrPullBinding) string {
				return binding.Spec.ServiceAccountName
			},
			GetPullSecretName: func(binding *msiacrpullv1beta2.AcrPullBinding) string {
				return pullSecretName(binding.ObjectMeta.Name)
			},
			GetInputsHash: func(binding *msiacrpullv1beta2.AcrPullBinding) string {
				return inputsHash(binding.Spec)
			},
			CreatePullCredential: func(ctx context.Context, binding *msiacrpullv1beta2.AcrPullBinding, serviceAccount *corev1.ServiceAccount) (string, time.Time, error) {
				var tenantId, clientId, token string
				if binding.Spec.Auth.WorkloadIdentity != nil {
					if binding.Spec.Auth.WorkloadIdentity.TenantID != "" {
						tenantId = binding.Spec.Auth.WorkloadIdentity.TenantID
						clientId = binding.Spec.Auth.WorkloadIdentity.ClientID
					} else {
						for _, annotation := range []struct { // n.b. we need an array here to be able to test for the error output
							value string
							into  *string
						}{
							{value: azworkloadidentity.ClientIDAnnotation, into: &clientId},
							{value: azworkloadidentity.TenantIDAnnotation, into: &tenantId},
						} {
							value, set := serviceAccount.Annotations[annotation.value]
							if !set {
								return "", time.Time{}, fmt.Errorf("service account %s missing %s annotation", serviceAccount.Name, annotation.value)
							}
							*annotation.into = value
						}
					}

					response, err := opts.mintToken(ctx, serviceAccount.Namespace, serviceAccount.Name)
					if err != nil {
						return "", time.Time{}, fmt.Errorf("failed to mint service account token: %w", err)
					}
					token = response.Status.Token
				}

				armToken, err := opts.fetchArmToken(ctx, binding.Spec, tenantId, clientId, token)
				if err != nil {
					return "", time.Time{}, fmt.Errorf("failed to retrieve ARM token: %v", err)
				}

				acrToken, err := opts.exchangeArmTokenForAcrToken(ctx, armToken, binding.Spec.ACR)
				if err != nil {
					return "", time.Time{}, fmt.Errorf("failed to retrieve ACR token: %v", err)
				}

				dockerConfig, err := authorizer.CreateACRDockerCfg(binding.Spec.ACR.Server, acrToken)
				if err != nil {
					return "", time.Time{}, fmt.Errorf("failed to write ACR dockercfg: %v", err)
				}
				return dockerConfig, acrToken.ExpiresOn, nil
			},
			UpdateStatusError: func(binding *msiacrpullv1beta2.AcrPullBinding, s string) *msiacrpullv1beta2.AcrPullBinding {
				updated := binding.DeepCopy()
				updated.Status.Error = s
				return updated
			},
			NeedsRefresh: func(logger logr.Logger, pullSecret *corev1.Secret, now func() time.Time) bool {
				return needsRefresh(now, pullSecretRefresh(logger, pullSecret), pullSecretExpiry(logger, pullSecret), opts.TTLRotationFraction)
			},
			RequeueAfter: func(now func() time.Time) func(binding *msiacrpullv1beta2.AcrPullBinding) time.Duration {
				return func(binding *msiacrpullv1beta2.AcrPullBinding) time.Duration {
					var requeueAfter time.Duration
					if binding.Status.TokenExpirationTime != nil && binding.Status.LastTokenRefreshTime != nil {
						refresh, expiry := binding.Status.LastTokenRefreshTime.Time, binding.Status.TokenExpirationTime.Time
						requeueAfter = refreshBoundary(refresh, expiry, opts.TTLRotationFraction).Sub(now())
					}
					return requeueAfter
				}
			},
			NeedsStatusUpdate: func(refresh time.Time, expiry time.Time, binding *msiacrpullv1beta2.AcrPullBinding) bool {
				return binding.Status.Error != "" || binding.Status.TokenExpirationTime == nil || !binding.Status.TokenExpirationTime.Equal(&metav1.Time{Time: expiry}) ||
					binding.Status.LastTokenRefreshTime == nil || !binding.Status.LastTokenRefreshTime.Equal(&metav1.Time{Time: refresh})
			},
			UpdateStatus: func(refresh time.Time, expiry time.Time, binding *msiacrpullv1beta2.AcrPullBinding) *msiacrpullv1beta2.AcrPullBinding {
				updated := binding.DeepCopy()
				updated.Status.TokenExpirationTime = &metav1.Time{Time: expiry}
				updated.Status.LastTokenRefreshTime = &metav1.Time{Time: refresh}
				updated.Status.Error = ""
				return updated
			},
			now: opts.now,
		},
	}
}

// PullBindingReconciler reconciles AcrPullBindings
type PullBindingReconciler struct {
	*genericReconciler[*msiacrpullv1beta2.AcrPullBinding]
}

func (r *PullBindingReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(ctx, &msiacrpullv1beta2.AcrPullBinding{}, serviceAccountField, indexV1beta2PullBindingByServiceAccount); err != nil {
		return err
	}
	// n.b. we do not need to add the imagePullSecretsField indexer on service accounts since v1beta1 controller does it
	// n.b. we do not need to add the pullBindingField indexer on service accounts since v1beta1 controller does it

	return ctrl.NewControllerManagedBy(mgr).
		For(&msiacrpullv1beta2.AcrPullBinding{}).
		Named("acr-pull-binding-v1beta2").
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(enqueuePullBindingsForPullSecret(mgr))).
		Watches(&corev1.ServiceAccount{}, handler.EnqueueRequestsFromMapFunc(enqueueV1beta2PullBindingsForServiceAccount(mgr))).
		Complete(r)
}

func indexV1beta2PullBindingByServiceAccount(object crclient.Object) []string {
	acrPullBinding, ok := object.(*msiacrpullv1beta2.AcrPullBinding)
	if !ok {
		return nil
	}

	return []string{acrPullBinding.Spec.ServiceAccountName}
}

func enqueueV1beta2PullBindingsForServiceAccount(mgr ctrl.Manager) func(ctx context.Context, object crclient.Object) []reconcile.Request {
	return func(ctx context.Context, object crclient.Object) []reconcile.Request {
		var pullBindings msiacrpullv1beta2.AcrPullBindingList
		if err := mgr.GetClient().List(ctx, &pullBindings, crclient.InNamespace(object.GetNamespace()), crclient.MatchingFields{serviceAccountField: object.GetName()}); err != nil {
			return nil
		}
		var requests []reconcile.Request
		for _, pullBinding := range pullBindings.Items {
			requests = append(requests, reconcile.Request{
				NamespacedName: crclient.ObjectKeyFromObject(&pullBinding),
			})
		}
		return requests
	}
}

//+kubebuilder:rbac:groups=acrpull.microsoft.com,resources=acrpullbindings,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=acrpull.microsoft.com,resources=acrpullbindings/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=acrpull.microsoft.com,resources=acrpullbindings/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=*
//+kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create

// inputsHash captures all the inputs for the pull binding which, if changed, would require a token regeneration
func inputsHash(spec msiacrpullv1beta2.AcrPullBindingSpec) string {
	inputs := []byte(spec.ServiceAccountName)
	switch {
	case spec.Auth.ManagedIdentity != nil:
		inputs = append(inputs, []byte("managedIdentity"+spec.Auth.ManagedIdentity.ResourceID+spec.Auth.ManagedIdentity.ClientID)...)
	case spec.Auth.WorkloadIdentity != nil:
		inputs = append(inputs, []byte("workloadIdentity"+spec.Auth.WorkloadIdentity.ServiceAccountName)...)
	}
	inputs = append(inputs, []byte(string(spec.ACR.Environment)+spec.ACR.Server+spec.ACR.Scope)...)
	return base36sha224(inputs)
}

// refreshBoundary determines when the TTL fraction required for rotation will have passed
func refreshBoundary(refresh, expiry time.Time, ttlRotationFraction float64) time.Time {
	ttl := expiry.Sub(refresh)
	return refresh.Add(time.Duration(float64(ttl) * ttlRotationFraction))
}

// needsRefresh determines if the TTL fraction required for rotation has passed since the last refresh
func needsRefresh(now func() time.Time, refresh, expiry time.Time, ttlRotationFraction float64) bool {
	return now().After(refreshBoundary(refresh, expiry, ttlRotationFraction))
}
