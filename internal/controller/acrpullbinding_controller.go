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
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
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

// V1beta1ReconcilerOpts configures the inputs for reconciling v1beta2 pull bindings
type V1beta1ReconcilerOpts struct {
	CoreOpts

	Auth                             authorizer.Interface
	DefaultManagedIdentityResourceID string
	DefaultManagedIdentityClientID   string
	DefaultACRServer                 string
	PullBindingLabelSelectorString   string
}

func NewV1beta1Reconciler(opts *V1beta1ReconcilerOpts) *AcrPullBindingReconciler {
	if opts.now == nil {
		opts.now = time.Now
	}

	return &AcrPullBindingReconciler{
		&genericReconciler[*msiacrpullv1beta1.AcrPullBinding]{
			Client: opts.Client,
			Logger: opts.Logger,
			Scheme: opts.Scheme,
			NewBinding: func() *msiacrpullv1beta1.AcrPullBinding {
				return &msiacrpullv1beta1.AcrPullBinding{}
			},
			AddFinalizer: func(binding *msiacrpullv1beta1.AcrPullBinding, finalizer string) *msiacrpullv1beta1.AcrPullBinding {
				updated := binding.DeepCopy()
				updated.ObjectMeta.Finalizers = append(updated.ObjectMeta.Finalizers, finalizer)
				return updated
			},
			RemoveFinalizer: func(binding *msiacrpullv1beta1.AcrPullBinding, finalizer string) *msiacrpullv1beta1.AcrPullBinding {
				updated := binding.DeepCopy()
				updated.ObjectMeta.Finalizers = slices.DeleteFunc(updated.ObjectMeta.Finalizers, func(s string) bool {
					return s == finalizer
				})
				return updated
			},
			GetServiceAccountName: func(binding *msiacrpullv1beta1.AcrPullBinding) string {
				serviceAccountName := binding.Spec.ServiceAccountName
				if serviceAccountName == "" {
					serviceAccountName = defaultServiceAccountName
				}
				return serviceAccountName
			},
			GetPullSecretName: func(binding *msiacrpullv1beta1.AcrPullBinding) string {
				return legacySecretName(binding.ObjectMeta.Name)
			},
			GetInputsHash: func(binding *msiacrpullv1beta1.AcrPullBinding) string {
				msiClientID, msiResourceID, acrServer := specOrDefault(opts, binding.Spec)
				return base36sha224([]byte(msiClientID + msiResourceID + acrServer + binding.Spec.Scope))
			},
			CreatePullCredential: func(ctx context.Context, logger logr.Logger, binding *msiacrpullv1beta1.AcrPullBinding, serviceAccount *corev1.ServiceAccount) (string, time.Time, error) {
				msiClientID, msiResourceID, acrServer := specOrDefault(opts, binding.Spec)
				acrAccessToken, err := opts.Auth.AcquireACRAccessToken(ctx, msiResourceID, msiClientID, acrServer, binding.Spec.Scope)
				if err != nil {
					return "", time.Time{}, fmt.Errorf("failed to retrieve ACR access token: %w", err)
				}

				dockerConfig, err := authorizer.CreateACRDockerCfg(acrServer, acrAccessToken)
				if err != nil {
					return "", time.Time{}, fmt.Errorf("failed to write ACR dockercfg: %v", err)
				}

				return dockerConfig, acrAccessToken.ExpiresOn, nil
			},
			UpdateStatusError: func(binding *msiacrpullv1beta1.AcrPullBinding, s string) *msiacrpullv1beta1.AcrPullBinding {
				updated := binding.DeepCopy()
				updated.Status.Error = s
				return updated
			},
			NeedsRefresh: func(logger logr.Logger, pullSecret *corev1.Secret, now func() time.Time) bool {
				return now().After(pullSecretExpiry(logger, pullSecret).Add(-1 * tokenRefreshBuffer))
			},
			RequeueAfter: func(now func() time.Time) func(binding *msiacrpullv1beta1.AcrPullBinding) time.Duration {
				return func(binding *msiacrpullv1beta1.AcrPullBinding) time.Duration {
					var requeueAfter time.Duration
					if binding.Status.TokenExpirationTime != nil {
						requeueAfter = binding.Status.TokenExpirationTime.Time.Add(-1 * tokenRefreshBuffer).Sub(now())
					}
					return requeueAfter
				}
			},
			NeedsStatusUpdate: func(refresh time.Time, expiry time.Time, binding *msiacrpullv1beta1.AcrPullBinding) bool {
				return binding.Status.Error != "" || binding.Status.TokenExpirationTime == nil || !binding.Status.TokenExpirationTime.Equal(&metav1.Time{Time: expiry}) ||
					binding.Status.LastTokenRefreshTime == nil || !binding.Status.LastTokenRefreshTime.Equal(&metav1.Time{Time: refresh})
			},
			UpdateStatus: func(refresh time.Time, expiry time.Time, binding *msiacrpullv1beta1.AcrPullBinding) *msiacrpullv1beta1.AcrPullBinding {
				updated := binding.DeepCopy()
				updated.Status.TokenExpirationTime = &metav1.Time{Time: expiry}
				updated.Status.LastTokenRefreshTime = &metav1.Time{Time: refresh}
				updated.Status.Error = ""
				return updated
			},
			LabelSelector: func() (labels.Selector, error) {
				return acrPullBindingLabelSelector(opts.PullBindingLabelSelectorString)
			},
			now: opts.now,
		},
	}
}

// AcrPullBindingReconciler reconciles a AcrPullBinding object
type AcrPullBindingReconciler struct {
	*genericReconciler[*msiacrpullv1beta1.AcrPullBinding]
}

//+kubebuilder:rbac:groups=msi-acrpull.microsoft.com,resources=acrpullbindings,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=msi-acrpull.microsoft.com,resources=acrpullbindings/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=msi-acrpull.microsoft.com,resources=acrpullbindings/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=*
//+kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;update;patch

func specOrDefault(opts *V1beta1ReconcilerOpts, spec msiacrpullv1beta1.AcrPullBindingSpec) (string, string, string) {
	msiClientID := spec.ManagedIdentityClientID
	msiResourceID := path.Clean(spec.ManagedIdentityResourceID)
	acrServer := spec.AcrServer
	if msiClientID == "" {
		msiClientID = opts.DefaultManagedIdentityClientID
	}
	if msiResourceID == "." {
		msiResourceID = opts.DefaultManagedIdentityResourceID
	}
	if acrServer == "" {
		acrServer = opts.DefaultACRServer
	}
	return msiClientID, msiResourceID, acrServer
}

// pullSecretExpiry determines when a pull credential stored in a Secret expires
func pullSecretExpiry(log logr.Logger, secret *corev1.Secret) time.Time {
	return extractPullSecretTimeAnnotation(log, secret, tokenExpiryAnnotation)
}

// pullSecretRefresh determines when a pull credential stored in a Secret was last refreshed
func pullSecretRefresh(log logr.Logger, secret *corev1.Secret) time.Time {
	return extractPullSecretTimeAnnotation(log, secret, tokenRefreshAnnotation)
}

// acrPullBindingLabelSelector parses a label selector string into a labels.Selector.
func acrPullBindingLabelSelector(labelSelectorString string) (labels.Selector, error) {
	trimmed := strings.TrimSpace(labelSelectorString)
	if trimmed == "" {
		return nil, nil
	}

	selector, err := labels.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("failed to parse label selector %q: %w", trimmed, err)
	}

	return selector, nil
}

// extractPullSecretTimeAnnotation extracts a timestamp from an annotation on the secret
func extractPullSecretTimeAnnotation(log logr.Logger, secret *corev1.Secret, annotation string) time.Time {
	if secret == nil {
		return time.Time{}
	}

	formattedTime, annotated := secret.Annotations[annotation]
	if !annotated {
		return time.Time{}
	}

	timestamp, err := time.Parse(time.RFC3339, formattedTime)
	if err != nil {
		// we should never get into this state unless some other actor corrupts our annotation,
		// so we can consider this token expired and re-generate it to get back to a good state
		log.WithValues("secret", client.ObjectKeyFromObject(secret).String()).WithValues("annotation", annotation).Error(err, "unexpected error parsing annotation on secret")
		return time.Time{}
	}

	return timestamp
}

func (r *AcrPullBindingReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	if r.now == nil {
		r.now = time.Now
	}
	if err := mgr.GetFieldIndexer().IndexField(ctx, &msiacrpullv1beta1.AcrPullBinding{}, serviceAccountField, indexPullBindingByServiceAccount); err != nil {
		return err
	}
	if err := mgr.GetFieldIndexer().IndexField(ctx, &corev1.Secret{}, pullBindingField, indexPullSecretByPullBinding); err != nil {
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
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(enqueuePullBindingsForPullSecret(mgr))).
		Watches(&corev1.ServiceAccount{}, handler.EnqueueRequestsFromMapFunc(enqueuePullBindingsForServiceAccount(mgr))).
		Complete(r)
}

func indexPullSecretByPullBinding(object client.Object) []string {
	pullSecret, ok := object.(*corev1.Secret)
	if !ok {
		return nil
	}

	if pullBindingName, labelled := pullSecret.Labels[ACRPullBindingLabel]; labelled {
		return []string{pullBindingName}
	}

	// while we clean up legacy secrets and add labels to them, we need to handle un-labelled secrets here
	if isLegacySecretName(pullSecret.ObjectMeta.Name) {
		return []string{pullBindingNameFromLegacySecret(pullSecret.ObjectMeta.Name)}
	}

	return nil
}

func enqueuePullBindingsForPullSecret(_ ctrl.Manager) func(ctx context.Context, object client.Object) []reconcile.Request {
	return func(ctx context.Context, object client.Object) []reconcile.Request {
		pullSecret, ok := object.(*corev1.Secret)
		if !ok {
			return nil
		}

		var pullBindingName string
		if name, labelled := pullSecret.Labels[ACRPullBindingLabel]; labelled {
			pullBindingName = name
		} else if isLegacySecretName(pullSecret.ObjectMeta.Name) {
			pullBindingName = pullBindingNameFromLegacySecret(pullSecret.ObjectMeta.Name)
		}
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: pullSecret.Namespace, Name: pullBindingName}}}
	}
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
	maxNameLength        = 253 /* longest object name */ - 10 /* length of static content */ - 10 /* length of hash */
	pullSecretNamePrefix = "acr-pull-"
)

// pullSecretName generates a human-readable name that marks this secret as being a pull secret, while
// ensuring that the name that's chosen will be a valid k8s Secret name, regardless of the input.
// We want the common case to produce a name that's easy to determine a priori, since we expect users to
// explicitly place the secret into their PodSpec.
// Example validations for Secret names:
// error: failed to create secret "..." is invalid: metadata.name: Invalid value: "...": must be no more than 253 characters
// error: failed to create secret "..." is invalid: metadata.name: Invalid value: "...": a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')
func pullSecretName(acrBindingName string) string {
	suffix := acrBindingName
	if len(suffix) > maxNameLength {
		suffix = suffix[:maxNameLength]
		suffix = strings.TrimSuffix(suffix, ".") // trailing domain label separators can't be followed by '-'
		suffix = suffix + "-" + base36sha224([]byte(acrBindingName))[:10]
	}
	return pullSecretNamePrefix + suffix
}

func isSecretName(pullSecretName string) bool {
	return strings.HasPrefix(pullSecretName, pullSecretNamePrefix)
}

const legacyPullSecretSuffix = "-msi-acrpull-secret"

func isLegacySecretName(pullSecretName string) bool {
	return strings.HasSuffix(pullSecretName, legacyPullSecretSuffix)
}

func pullBindingNameFromLegacySecret(pullSecretName string) string {
	return strings.TrimSuffix(pullSecretName, legacyPullSecretSuffix)
}

func legacySecretName(acrBindingName string) string {
	return acrBindingName + legacyPullSecretSuffix
}

func newPullSecret(acrBinding client.Object,
	name, dockerConfig string, scheme *runtime.Scheme, expiry time.Time, now func() time.Time, inputHash string) *corev1.Secret {

	pullSecret := &corev1.Secret{
		Type: corev1.SecretTypeDockerConfigJson,
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				ACRPullBindingLabel: acrBinding.GetName(),
			},
			Annotations: map[string]string{
				tokenExpiryAnnotation:  expiry.Format(time.RFC3339),
				tokenRefreshAnnotation: now().Format(time.RFC3339),
				tokenInputsAnnotation:  inputHash,
			},
			Name:      name,
			Namespace: acrBinding.GetNamespace(),
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
