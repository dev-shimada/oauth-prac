package main

type Session struct {
	client string
	scopes string
	// nonce string
	// IDトークンを払い出すか否か、trueならIDトークンもfalseならOAuthでトークンだけ払い出す
	// oidc bool
}

// type Client struct {
// 	id          string
// 	name        string
// 	redirectURL string
// 	secret      string
// }

// type User struct {
// 	id          int
// 	name        string
// 	password    string
// 	sub         string
// 	name_ja     string
// 	given_name  string
// 	family_name string
// 	locale      string
// }

// type AuthCode struct {
// 	user         string
// 	clientId     string
// 	scopes       string
// 	redirect_uri string
// 	expires_at   int64
// }

// type TokenCode struct {
// 	user       string
// 	clientId   string
// 	scopes     string
// 	expires_at int64
// }

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IdToken     string `json:"id_token,omitempty"`
}
