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

	mth, err := auth.NewMethod("secret", auth.Claim(*cnf))
	if err != nil {
		panic(err)
	}

	log.Printf("Token: %s", mth.Token())
}
