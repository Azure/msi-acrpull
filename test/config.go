package test

import (
	"fmt"
	"os"

	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
	msiacrpullv1beta2 "github.com/Azure/msi-acrpull/api/v1beta2"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	clientgorest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type Config struct {
	// Images stored in an ACR that requires authentication to pull, but in different repositories.
	AliceImage string
	BobImage   string

	// ARM resource ID for the puller MSI
	PullerResourceID string
	// Client ID for the puller MSI
	PullerClientID string
	// Tenant ID for the puller MSI
	PullerTenantID string
	// FQDN for the registry we're pulling from
	RegistryFQDN string
	// Label selector for the nodes we need to schedule to
	LabelSelector string

	// Path of authentication config for the AKS cluster.
	KubeconfigPath string
}

func LoadConfig() (*Config, error) {
	cfg := &Config{}
	for env, into := range map[string]*string{
		"ALICE_IMAGE":      &cfg.AliceImage,
		"BOB_IMAGE":        &cfg.BobImage,
		"PULLER_ID":        &cfg.PullerResourceID,
		"PULLER_CLIENT_ID": &cfg.PullerClientID,
		"PULLER_TENANT_ID": &cfg.PullerTenantID,
		"ACR_FQDN":         &cfg.RegistryFQDN,
		"LABEL_SELECTOR":   &cfg.LabelSelector,
		"KUBECONFIG":       &cfg.KubeconfigPath,
	} {
		value, set := os.LookupEnv(env)
		if !set {
			return nil, fmt.Errorf("env variable %s not set", env)
		}
		*into = value
	}
	return cfg, nil
}

func ClientFor(cfg *Config, clientOpts ...func(*clientgorest.Config)) (crclient.Client, error) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("could not add Kubernetes types to scheme: %w", err)
	}

	if err := msiacrpullv1beta1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("could not add msi-acrpull v1beta1 types to scheme: %w", err)
	}
	if err := msiacrpullv1beta2.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("could not add msi-acrpull v1beta2 types to scheme: %w", err)
	}
	clientConfig, err := RestConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("error loading config: %v", err)
	}
	for _, opt := range clientOpts {
		opt(clientConfig)
	}
	client, err := crclient.New(clientConfig, crclient.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("error creating client: %v", err)
	}
	return client, nil
}

func RestConfig(cfg *Config) (*clientgorest.Config, error) {
	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(&clientcmd.ClientConfigLoadingRules{
		ExplicitPath: cfg.KubeconfigPath,
	}, nil)
	clientConfig, err := loader.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("error loading config: %v", err)
	}
	clientConfig.QPS = -1
	clientConfig.Burst = -1
	return clientConfig, nil
}
