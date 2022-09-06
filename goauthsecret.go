package main

import (
	"context"
	"fmt"
	"log"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

var (
	cacheAccessor = &TokenCache{"serialized_cache.json"}
)

func acquireTokenClientSecret() {
	config := CreateConfig("config.json")
	cred, err := confidential.NewCredFromSecret(config.ClientSecret)
	if err != nil {
		log.Fatal(err)
	}

	app, err := confidential.New(config.ClientID, cred, confidential.WithAuthority(config.Authority), confidential.WithAccessor(cacheAccessor))
	if err != nil {
		log.Fatal(err)
	}

	result, err := app.AcquireTokenSilent(context.Background(), config.Scopes)
	if err != nil {
		result, err = app.AcquireTokenByCredential(context.Background(), config.Scopes)
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
