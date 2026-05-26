package controller

import (
	"strings"
	"testing"
)

func Test_validateACRServerSuffix(t *testing.T) {
	for _, testCase := range []struct {
		name            string
		acrServer       string
		allowedSuffixes []string
		wantErr         string
	}{
		{
			name:            "empty allow list preserves legacy behavior",
			acrServer:       "attacker.example.com",
			allowedSuffixes: nil,
		},
		{
			name:            "subdomain of configured suffix is allowed",
			acrServer:       "registry.azurecr.io",
			allowedSuffixes: []string{"azurecr.io"},
		},
		{
			name:            "suffix matching is case insensitive",
			acrServer:       "Registry.AzureCR.IO",
			allowedSuffixes: []string{".AZURECR.IO."},
		},
		{
			name:            "exact configured domain is allowed",
			acrServer:       "registry.internal",
			allowedSuffixes: []string{"registry.internal"},
		},
		{
			name:            "lookalike suffix is rejected",
			acrServer:       "registry.azurecr.io.attacker.example.com",
			allowedSuffixes: []string{"azurecr.io"},
			wantErr:         `ACR server "registry.azurecr.io.attacker.example.com" is not in the allowed ACR server suffixes: azurecr.io`,
		},
		{
			name:            "paths are rejected when validation is configured",
			acrServer:       "registry.azurecr.io/oauth2/exchange",
			allowedSuffixes: []string{"azurecr.io"},
			wantErr:         `ACR server "registry.azurecr.io/oauth2/exchange" is invalid: server must be a host name without scheme, path, query, or fragment`,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			err := validateACRServerSuffix(testCase.acrServer, testCase.allowedSuffixes)
			if testCase.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", testCase.wantErr)
			}
			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("expected error containing %q, got %q", testCase.wantErr, err.Error())
			}
		})
	}
}
