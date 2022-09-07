package auth

import (
	"context"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// AuthMethodSecret is a container for Claims and Permits obtained
type AuthMethodSecret struct {
	Claim
	Permit
}

// acquireTokenClientSecret does auth request for a method
func acquireTokenClientSecret(clm Claim) (string, error) {
	crd, err := confidential.NewCredFromSecret(clm.ClientSecret)
	if err != nil {
		return "", err
	}

	app, err := confidential.New(clm.ClientID, crd, confidential.WithAuthority(clm.Authority), confidential.WithAccessor(cacheAccessor))
	if err != nil {
		return "", err
	}

	result, err := app.AcquireTokenSilent(context.Background(), clm.Scopes)
	if err != nil {
		result, err = app.AcquireTokenByCredential(context.Background(), clm.Scopes)
		if err != nil {
			return "", err
		}
	}

	return result.AccessToken, nil
}

// NewAuthMethodSecret creates new object with original claim and a permit
func NewAuthMethodSecret(clm Claim) (AuthMethodSecret, error) {
	token, err := acquireTokenClientSecret(clm)
	if err != nil {
		return AuthMethodSecret{Claim{}, Permit{}}, err
	}

	return AuthMethodSecret{clm, Permit{token}}, nil
}

// Token gives out the permit artefact
func (m AuthMethodSecret) Token() string {
	return m.Permit.token
}
