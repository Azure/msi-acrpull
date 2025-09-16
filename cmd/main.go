package main

import (
	"flag"
	"fmt"
	"os"

	msiacrpullv1beta2 "github.com/Azure/msi-acrpull/api/v1beta2"
	"github.com/Azure/msi-acrpull/internal/controller"
	"github.com/Azure/msi-acrpull/pkg/authorizer"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
	//+kubebuilder:scaffold:imports
)

const (
	defaultACRServerEnvKey                 = "ACR_SERVER"
	defaultManagedIdentityResourceIDEnvKey = "MANAGED_IDENTITY_RESOURCE_ID"
	defaultManagedIdentityClientIDEnvKey   = "MANAGED_IDENTITY_CLIENT_ID"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(msiacrpullv1beta1.AddToScheme(scheme))
	utilruntime.Must(msiacrpullv1beta2.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var serviceAccountTokenAudience string
	var ttlRotationFraction float64
	var labelSelectorString string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&serviceAccountTokenAudience, "service-account-token-audience", "api://AzureCRTokenExchange", "The audience to ask the Kubernetes API server to mint Service Account tokens for, must match Federated Identity Credential configuration in Azure.")
	flag.Float64Var(&ttlRotationFraction, "ttl-rotation-fraction", 0.5, "The fraction of the pull token's TTL at which the v1beta2 reconciler will refresh the token.")
	flag.StringVar(&labelSelectorString, "label-selector", "", "Label value to watch for AcrPullBindings")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	defaultACRServer := os.Getenv(defaultACRServerEnvKey)
	defaultManagedIdentityResourceID := os.Getenv(defaultManagedIdentityResourceIDEnvKey)
	defaultManagedIdentityClientID := os.Getenv(defaultManagedIdentityClientIDEnvKey)

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	cfg := ctrl.GetConfigOrDie()
	ctx := ctrl.SetupSignalHandler()
	client, err := crclient.New(cfg, crclient.Options{Scheme: scheme})
	if err != nil {
		setupLog.Error(err, "unable to create client")
		os.Exit(1)
	}

	var pullBindings msiacrpullv1beta1.AcrPullBindingList
	if err := client.List(ctx, &pullBindings); err != nil {
		setupLog.Error(err, "unable to fetch ACRPullBindings")
		os.Exit(1)
	}

	var secrets corev1.SecretList
	if err := client.List(ctx, &secrets); err != nil {
		setupLog.Error(err, "unable to fetch Secrets")
		os.Exit(1)
	}

	cleanupRequired := controller.LegacyPullSecretsPresentWithoutLabels(pullBindings, secrets)

	// when we've already cleaned up all legacy secrets, we can filter our
	// informers to only the set of secrets we create and manage
	var cacheOpts cache.Options
	if !cleanupRequired {
		setupLog.Info(fmt.Sprintf("filtering Secret informers for label %s", controller.ACRPullBindingLabel))
		requirement, err := labels.NewRequirement(controller.ACRPullBindingLabel, selection.Exists, []string{})
		if err != nil {
			setupLog.Error(err, "unable to create label selector")
			os.Exit(1)
		}
		cacheOpts = cache.Options{
			ByObject: map[crclient.Object]cache.ByObject{
				&corev1.Secret{}: {
					Label: labels.NewSelector().Add(*requirement),
				},
			},
		}
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Cache:                  cacheOpts,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "aks.azure.com",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}
	apbReconciler := controller.NewV1beta1Reconciler(&controller.V1beta1ReconcilerOpts{
		CoreOpts: controller.CoreOpts{
			Client: mgr.GetClient(),
			Logger: ctrl.Log.WithName("controller").WithName("AcrPullBinding"),
			Scheme: mgr.GetScheme(),
		},
		Auth:                             authorizer.NewAuthorizer(),
		DefaultManagedIdentityResourceID: defaultManagedIdentityResourceID,
		DefaultManagedIdentityClientID:   defaultManagedIdentityClientID,
		DefaultACRServer:                 defaultACRServer,
		PullBindingLabelSelectorString:   labelSelectorString,
	})
	if err := apbReconciler.SetupWithManager(ctx, mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AcrPullBinding")
		os.Exit(1)
	}

	kubeClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		setupLog.Error(err, "unable to create client")
	}

	v1beta2Reconciler := controller.NewV1beta2Reconciler(&controller.V1beta2ReconcilerOpts{
		CoreOpts: controller.CoreOpts{
			Client: mgr.GetClient(),
			Logger: ctrl.Log.WithName("controller").WithName("AcrPullBindingV1beta2"),
			Scheme: mgr.GetScheme(),
		},
		TTLRotationFraction:            ttlRotationFraction,
		ServiceAccountTokenAudience:    serviceAccountTokenAudience,
		ServiceAccountClient:           kubeClient.CoreV1(),
		PullBindingLabelSelectorString: labelSelectorString,
	})
	if err := v1beta2Reconciler.SetupWithManager(ctx, mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AcrPullBindingV1beta2")
		os.Exit(1)
	}

	if cleanupRequired {
		setupLog.Info("setting up controller to clean up legacy pull tokens")
		cleanupController := &controller.LegacyTokenCleanupController{
			Client: mgr.GetClient(),
			Log:    ctrl.Log.WithName("controllers").WithName("LegacyTokenCleanup"),
		}
		if err := cleanupController.SetupWithManager(ctx, mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "LegacyTokenCleanup")
			os.Exit(1)
		}
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
