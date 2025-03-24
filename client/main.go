package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var oidcLocal = oidc{
	iss:              "https://oreore.oidc.com",
	clientId:         "1234",
	clientSecret:     "secret",
	authEndpoint:     "http://localhost:8081/auth",
	tokenEndpoint:    "http://localhost:8081/token",
	userInfoEndpoint: "http://localhost:8081/userinfo",
	keyEndpoint:      "http://localhost:8081/certs",
	state:            "xyz",
	nonce:            "abc",
}

const (
	response_type = "code"
	redirect_uri  = "http://localhost:8080/callback"
	grant_type    = "authorization_code"

	scope = "openid profile"
	LOCAL = true
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/callback", callback)

	// Wait here until CTRL+C or other term signal is received
	ctx, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	// defer stop()

	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	log.Println("Server is running at :8080 Press CTRL-C to exit.")
	go srv.ListenAndServe()

	<-ctx.Done()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("HTTP server Shutdown: %v", err)
	}
}

func generateCodeVerifier() string {
	const length = 43
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	// init random seed
	rand.New(rand.NewSource(time.Now().UnixNano()))
	// create a random string
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}

	return string(b)
}

type CodeChallengeMethod string

const (
	CodeChallengePlain CodeChallengeMethod = "plain"
	CodeChallengeS256  CodeChallengeMethod = "S256"
)

// generateCodeChallenge generates a code challenge from a code verifier using the given code challenge method.
// If the code challenge method is "plain", the code challenge is the same as the code verifier.
// If the code challenge method is "S256", the code challenge is the base64-url-encoded SHA-256 hash of the code verifier.
func generateCodeChallenge(codeVerifier string, ccm CodeChallengeMethod) string {
	// If the code challenge method is "plain", the code challenge is the same as the code verifier
	if ccm == CodeChallengePlain {
		return codeVerifier
	}

	// Hash the code verifier using SHA-256
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	hashed := h.Sum(nil)

	// Base64-url-encode the hash and remove any padding
	codeChallenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hashed)

	return codeChallenge
}

func login(w http.ResponseWriter, req *http.Request) {
	codeVerifier := generateCodeVerifier()
	codeChallenge := generateCodeChallenge(codeVerifier, CodeChallengeS256)
	slog.Info(fmt.Sprintf("codeVerifier: %s", codeVerifier))
	slog.Info(fmt.Sprintf("codeChallenge: %s", codeChallenge))

	v := url.Values{}
	v.Add("response_type", response_type)
	v.Add("client_id", oidcLocal.clientId)
	v.Add("state", oidcLocal.state)
	v.Add("scope", scope)
	v.Add("redirect_uri", redirect_uri)
	v.Add("nonce", oidcLocal.nonce)
	v.Add("code_challenge", codeChallenge)
	v.Add("code_challenge_method", string(CodeChallengeS256))

	log.Printf("http redirect to: %s", fmt.Sprintf("%s?%s", oidcLocal.authEndpoint, v.Encode()))
	http.Redirect(w, req, fmt.Sprintf("%s?%s", oidcLocal.authEndpoint, v.Encode()), http.StatusFound)
}

func tokenRequest(query url.Values, c *http.Cookie) (map[string]interface{}, error) {

	v := url.Values{}
	v.Add("client_id", oidcLocal.clientId)
	v.Add("client_secret", oidcLocal.clientSecret)
	v.Add("grant_type", grant_type)
	v.Add("code", query.Get("code"))
	v.Add("redirect_uri", redirect_uri)
	v.Add("code_verifier", query.Get("code_verifier"))

	req, err := http.NewRequest("POST", oidcLocal.tokenEndpoint, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.AddCookie(c)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var token map[string]any
	json.Unmarshal(body, &token)

	log.Printf("token response :%s\n", string(body))

	return token, nil
}

func callback(w http.ResponseWriter, req *http.Request) {

	query := req.URL.Query()
	c, _ := req.Cookie("session")
	token, err := tokenRequest(query, c)
	if err != nil {
		log.Println(err)
	}

	id_token := token["id_token"].(string)
	verifyJWT(id_token)
	jwtdata := decodeJWT(id_token)
	err = verifyJWTSignature(jwtdata, id_token, oidcLocal)
	if err != nil {
		log.Printf("verify JWT Signature err : %s", err)
	}

	err = verifyToken(jwtdata, token["access_token"].(string), oidcLocal)
	if err != nil {
		log.Printf("verifyToken is err : %s", err)
	}

	userInfoURL := oidcLocal.userInfoEndpoint
	log.Println(userInfoURL)
	req, err = http.NewRequest("GET", userInfoURL, nil)
	if nil != err {
		log.Println(err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token["access_token"].(string)))
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
	}
	//log.Println(string(body))

	w.Write([]byte(body))

}
