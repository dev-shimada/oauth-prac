package main

type oidc struct {
	iss              string
	clientId         string
	clientSecret     string
	state            string
	authEndpoint     string
	tokenEndpoint    string
	userInfoEndpoint string
	keyEndpoint      string
	nonce            string
}
