package authorizer

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/time/rate"
)

const (
	defaultRPS   = 1
	defaultBurst = 5
)

type rateLimitedClient struct {
	httpClient  *http.Client
	rateLimiter *rate.Limiter
}

func newRateLimitedClient() *rateLimitedClient {
	return newRateLimitedClientWithRPS(defaultRPS, defaultBurst)
}

func newRateLimitedClientWithRPS(rps float64, burst int) *rateLimitedClient {
	client := &rateLimitedClient{
		httpClient:  http.DefaultClient,
		rateLimiter: rate.NewLimiter(rate.Limit(rps), burst),
	}
	return client
}

func (client *rateLimitedClient) Do(req *http.Request) (*http.Response, error) {
	ctx := context.Background()
	err := client.rateLimiter.Wait(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to wait for rate limit token: %w", err)
	}

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
