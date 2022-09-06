package main

import (
	"context"
	"fmt"
	"log"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"

	"goauthsecret/cache"
	"goauthsecret/config"
)

var (
	cacheAccessor = &cache.TokenCache{"cache.json"}
)

func acquireTokenClientSecret() {
	conf := config.CreateConfig("config.json")
	cred, err := confidential.NewCredFromSecret(conf.ClientSecret)
	if err != nil {
		log.Fatal(err)
	}

	app, err := confidential.New(conf.ClientID, cred, confidential.WithAuthority(conf.Authority), confidential.WithAccessor(cacheAccessor))
	if err != nil {
		log.Fatal(err)
	}

	result, err := app.AcquireTokenSilent(context.Background(), conf.Scopes)
	if err != nil {
		result, err = app.AcquireTokenByCredential(context.Background(), conf.Scopes)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Access Token Is " + result.AccessToken)
	}

	fmt.Println("Silently acquired token " + result.AccessToken)
}

func main() {
	acquireTokenClientSecret()
}
