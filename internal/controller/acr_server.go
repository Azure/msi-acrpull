package controller

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

func validateACRServerSuffix(acrServer string, allowedSuffixes []string) error {
	allowedSuffixes = normalizeACRServerSuffixes(allowedSuffixes)
	if len(allowedSuffixes) == 0 {
		return nil
	}

	hostname, err := acrServerHostname(acrServer)
	if err != nil {
		return fmt.Errorf("ACR server %q is invalid: %w", acrServer, err)
	}

	for _, suffix := range allowedSuffixes {
		if hostname == suffix || strings.HasSuffix(hostname, "."+suffix) {
			return nil
		}
	}

	return fmt.Errorf("ACR server %q is not in the allowed ACR server suffixes: %s", acrServer, strings.Join(allowedSuffixes, ", "))
}

func normalizeACRServerSuffixes(suffixes []string) []string {
	normalized := make([]string, 0, len(suffixes))
	seen := map[string]struct{}{}
	for _, suffix := range suffixes {
		suffix = strings.Trim(strings.ToLower(strings.TrimSpace(suffix)), ".")
		if suffix == "" {
			continue
		}
		if _, ok := seen[suffix]; ok {
			continue
		}
		seen[suffix] = struct{}{}
		normalized = append(normalized, suffix)
	}
	return normalized
}

func acrServerHostname(acrServer string) (string, error) {
	trimmed := strings.TrimSpace(acrServer)
	if trimmed == "" {
		return "", fmt.Errorf("server is empty")
	}

	endpoint, err := url.Parse("https://" + trimmed)
	if err != nil {
		return "", err
	}
	if endpoint.Host == "" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return "", fmt.Errorf("server must be a host name without scheme, path, query, or fragment")
	}
	if strings.Contains(endpoint.Host, ":") {
		if _, _, err := net.SplitHostPort(endpoint.Host); err != nil {
			return "", fmt.Errorf("server host is invalid: %w", err)
		}
	}

	hostname := strings.TrimSuffix(strings.ToLower(endpoint.Hostname()), ".")
	if hostname == "" {
		return "", fmt.Errorf("server hostname is empty")
	}
	return hostname, nil
}
