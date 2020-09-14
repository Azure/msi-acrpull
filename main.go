package main

import (
	"flag"
	"os"

	"github.com/Azure/msi-acrpull/controllers"
	"github.com/Azure/msi-acrpull/pkg/authorizer"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
	// +kubebuilder:scaffold:imports
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
	_ = clientgoscheme.AddToScheme(scheme)
	_ = msiacrpullv1beta1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.Parse()
	defaultACRServer := os.Getenv(defaultACRServerEnvKey)
	defaultManagedIdentityResourceID := os.Getenv(defaultManagedIdentityResourceIDEnvKey)
	defaultManagedIdentityClientID := os.Getenv(defaultManagedIdentityClientIDEnvKey)

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               9443,
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "aks.azure.com",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}
	apbReconciler := &controllers.AcrPullBindingReconciler{
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
	// +kubebuilder:scaffold:builder
	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
