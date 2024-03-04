package main

import (
	"flag"
	"os"

	"github.com/Azure/msi-acrpull/internal/controller"
	"github.com/Azure/msi-acrpull/pkg/authorizer"

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
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	defaultACRServer := os.Getenv(defaultACRServerEnvKey)
	defaultManagedIdentityResourceID := os.Getenv(defaultManagedIdentityResourceIDEnvKey)
	defaultManagedIdentityClientID := os.Getenv(defaultManagedIdentityClientIDEnvKey)

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "aks.azure.com",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	apbReconciler := &controller.AcrPullBindingReconciler{
		Client:                           mgr.GetClient(),
		Log:                              ctrl.Log.WithName("controllers").WithName("AcrPullBinding"),
		Scheme:                           mgr.GetScheme(),
		Auth:                             authorizer.NewAuthorizer(),
		DefaultACRServer:                 defaultACRServer,
		DefaultManagedIdentityResourceID: defaultManagedIdentityResourceID,
		DefaultManagedIdentityClientID:   defaultManagedIdentityClientID,
	}
	if err = apbReconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AcrPullBinding")
		os.Exit(1)
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
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
