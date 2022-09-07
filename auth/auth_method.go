// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package auth

import (
	"fmt"
	"goauthsecret/cache"
)

type Method interface {
	Token() string
}

type Permit struct {
	token string
}

type Claim struct {
	ClientID            string   `json:"client_id"`
	Authority           string   `json:"authority"`
	Scopes              []string `json:"scopes"`
	Username            string   `json:"username"`
	Password            string   `json:"password"`
	RedirectURI         string   `json:"redirect_uri"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
	State               string   `json:"state"`
	ClientSecret        string   `json:"client_secret"`
	Thumbprint          string   `json:"thumbprint"`
	PemData             string   `json:"pem_file"`
}

var (
	cacheAccessor = &cache.TokenCache{"cache.json"}
)

func NewMethod(method string, clm Claim) (Method, error) {
	switch method {
	case "secret":
		return NewAuthMethodSecret(clm)
	case "certificate":
		return NewAuthMethodCertificate(clm)
	}

	return nil, fmt.Errorf("Invalid method requested: %s", method)
}
