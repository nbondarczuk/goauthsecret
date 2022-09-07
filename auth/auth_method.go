// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package auth

import (
	"fmt"
	"goauthsecret/cache"
)

// Method is a generic container producing token
type Method interface {
	Token() string
}

// Permit is the result of auth process. It contain secrets to be used in communication.
type Permit struct {
	token string
}

// Claim is a set of possible authorisation requisits
type Claim struct {
	ClientID            string
	Authority           string
	Scopes              []string
	Username            string
	Password            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	ClientSecret        string
	Thumbprint          string
	PemData             string
}

// Vanilla unsafe cache, full implementation TBD
var (
	cacheAccessor = &cache.TokenCache{"cache.json"}
)

// NeMethod is a factory producing Permits using Claims provided
func NewMethod(method string, clm Claim) (Method, error) {
	switch method {
	case "secret":
		return NewAuthMethodSecret(clm)
	case "certificate":
		return NewAuthMethodCertificate(clm)
	}

	return nil, fmt.Errorf("Invalid method requested: %s", method)
}
