package main

import (
	"log"

	"goauthsecret/auth"
	"goauthsecret/config"
)

func main() {
	cnf, err := config.NewConfig("config.json")
	if err != nil {
		panic(err)
	}

	// Silently converting config to claim, ie. claim is loaded from config
	mth, err := auth.NewMethod("secret", auth.Claim(*cnf))
	if err != nil {
		panic(err)
	}

	log.Printf("Token: %+v -> %s", *cnf, mth.Token())
}
