package authorizer

// Interface is the authorizer interface to acquire ACR access tokens.
type Interface interface {
	AcquireACRAccessTokenWithResourceID(identityResourceID string, acrFQDN string) (AccessToken, error)
	AcquireACRAccessTokenWithClientID(clientID string, acrFQDN string) (AccessToken, error)
}

// ManagedIdentityTokenRetriever is the interface to acquire an ARM access token.
type ManagedIdentityTokenRetriever interface {
	AcquireARMToken(clientID string, resourceID string) (AccessToken, error)
}

// ACRTokenExchanger is the interface to exchange an ACR access token.
type ACRTokenExchanger interface {
	ExchangeACRAccessToken(armToken AccessToken, acrFQDN string) (AccessToken, error)
}
