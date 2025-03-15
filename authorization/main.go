package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dev-shimada/oidc-prac/authorization/internal/jwt"
	"github.com/google/uuid"
)

const (
	//SCOPE                 = "readonly"
	SCOPE                 = "https://www.googleapis.com/auth/photoslibrary.readonly"
	AUTH_CODE_DURATION    = 300
	ACCESS_TOKEN_DURATION = 3600
)

var clientInfo = Client{
	id:          "1234",
	name:        "test",
	redirectURL: "http://localhost:8080/callback",
	secret:      "secret",
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})
	mux.HandleFunc("/auth", auth)
	mux.HandleFunc("/authcheck", authCheck)
	mux.HandleFunc("/token", token)
	mux.HandleFunc("/certs", certs)
	mux.HandleFunc("/userinfo", userinfo)

	// Wait here until CTRL+C or other term signal is received
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:    ":8081",
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

var sessionList = make(map[string]Session)

func auth(w http.ResponseWriter, req *http.Request) {
	query := req.URL.Query()
	requiredParameter := []string{"response_type", "client_id", "redirect_uri"}
	// 必須パラメータのチェック
	for _, v := range requiredParameter {
		if !query.Has(v) {
			log.Printf("%s is missing", v)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("invalid_request. %s is missing", v)))
			return
		}
	}
	// client id の一致確認
	if clientInfo.id != query.Get("client_id") {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("client_id is not match"))
		return
	}
	// レスポンスタイプはいったん認可コードだけをサポート
	if query.Get("response_type") != "code" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("only support code"))
		return
	}
	sessionId := uuid.New().String()
	// セッションを保存しておく
	session := Session{
		client:                query.Get("client_id"),
		state:                 query.Get("state"),
		scopes:                query.Get("scope"),
		redirectUri:           query.Get("redirect_uri"),
		code_challenge:        query.Get("code_challenge"),
		code_challenge_method: query.Get("code_challenge_method"),
	}
	sessionList[sessionId] = session

	// CookieにセッションIDをセット
	cookie := &http.Cookie{
		Name:  "session",
		Value: sessionId,
	}
	http.SetCookie(w, cookie)

	// ログイン&権限認可の画面を戻す
	var templates = make(map[string]*template.Template)
	var err error
	if templates["login"], err = template.ParseFiles("login.html"); err != nil {
		log.Fatal(err)
	}
	if err := templates["login"].Execute(w, struct {
		ClientId string
		Scope    string
	}{
		ClientId: session.client,
		Scope:    session.scopes,
	}); err != nil {
		log.Println(err)
	}
	log.Println("return login page...")

}

var user = User{
	id:          1111,
	name:        "hoge",
	password:    "password",
	sub:         "11111111",
	name_ja:     "徳川慶喜",
	given_name:  "慶喜",
	family_name: "徳川",
	locale:      "ja",
}

func authCheck(w http.ResponseWriter, req *http.Request) {

	loginUser := req.FormValue("username")
	password := req.FormValue("password")

	if loginUser != user.name || password != user.password {
		w.Write([]byte("login failed"))
	} else {

		cookie, _ := req.Cookie("session")
		http.SetCookie(w, cookie)

		v := sessionList[cookie.Value]

		authCodeString := uuid.New().String()
		authData := AuthCode{
			user:         loginUser,
			clientId:     v.client,
			scopes:       v.scopes,
			redirect_uri: v.redirectUri,
			expires_at:   time.Now().Unix() + 300,
		}
		// 認可コードを保存
		// var AuthCodeList = make(map[string]AuthCode)
		// AuthCodeList[authCodeString] = authData

		log.Printf("auth code accepet : %v\n", authData)

		location := fmt.Sprintf("%s?code=%s&state=%s", v.redirectUri, authCodeString, v.state)
		w.Header().Add("Location", location)
		w.WriteHeader(302)

	}

}

// https://auth0.com/docs/authorization/flows/call-your-api-using-the-authorization-code-flow-with-pkce#javascript-sample
func base64URLEncode(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

var AuthCodeList = make(map[string]AuthCode)
var TokenCodeList = make(map[string]TokenCode)

// トークンを発行するエンドポイント
func token(w http.ResponseWriter, req *http.Request) {

	cookie, _ := req.Cookie("session")
	req.ParseForm()
	query := req.Form

	requiredParameter := []string{"grant_type", "code", "client_id", "redirect_uri"}
	// 必須パラメータのチェック
	for _, v := range requiredParameter {
		if !query.Has(v) {
			log.Printf("%s is missing", v)
			w.WriteHeader(http.StatusBadRequest)
			b := make([]byte, 0)
			w.Write(fmt.Appendf(b, "invalid_request. %s is missing\n", v))
			return
		}
	}

	// 認可コードフローだけサポート
	if query.Get("grant_type") != "authorization_code" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid_request. not support type.\n"))
	}

	// 保存していた認可コードのデータを取得。なければエラーを返す
	v, ok := AuthCodeList[query.Get("code")]
	if !ok {
		log.Println("auth code isn't exist")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("no authrization code"))
	}

	// 認可リクエスト時のクライアントIDと比較
	if v.clientId != query.Get("client_id") {
		log.Println("client_id not match")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid_request. client_id not match.\n"))
	}

	// 認可リクエスト時のリダイレクトURIと比較
	if v.redirect_uri != query.Get("redirect_uri") {
		log.Println("redirect_uri not match")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid_request. redirect_uri not match.\n"))
	}

	// 認可コードの有効期限を確認
	if v.expires_at < time.Now().Unix() {
		log.Println("authcode expire")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid_request. auth code time limit is expire.\n"))
	}

	// clientシークレットの確認
	if clientInfo.secret != query.Get("client_secret") {
		log.Println("client_secret is not match.")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid_request. client_secret is not match.\n"))
	}

	// PKCEのチェック
	// clientから送られてきたverifyをsh256で計算&base64urlエンコードしてから
	// 認可リクエスト時に送られてきてセッションに保存しておいたchallengeと一致するか確認
	session := sessionList[cookie.Value]
	if session.code_challenge != base64URLEncode(query.Get("code_verifier")) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("PKCE check is err..."))
	}

	tokenString := uuid.New().String()
	expireTime := time.Now().Unix() + ACCESS_TOKEN_DURATION

	tokenInfo := TokenCode{
		user:       v.user,
		clientId:   v.clientId,
		scopes:     v.scopes,
		expires_at: expireTime,
	}
	TokenCodeList[tokenString] = tokenInfo
	// 認可コードを削除
	delete(AuthCodeList, query.Get("code"))

	tokenResp := TokenResponse{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		ExpiresIn:   expireTime,
	}
	resp, err := json.Marshal(tokenResp)
	if err != nil {
		log.Println("json marshal err")
	}

	log.Printf("token ok to client %s, token is %s", v.clientId, string(resp))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func certs(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write(jwt.MakeJWK())
}

func userinfo(w http.ResponseWriter, req *http.Request) {
	h := req.Header.Get("Authorization")
	tmp := strings.Split(h, " ")

	// トークンがあるか確認
	v, ok := TokenCodeList[tmp[1]]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("token is wrong.\n"))
		return
	}

	// トークンの有効期限が切れてないか
	if v.expires_at < time.Now().Unix() {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("token is expire.\n"))
		return
	}

	// スコープが正しいか、openid profileで固定
	if v.scopes != "openid profile" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("scope is not permit.\n"))
		return
	}

	// ユーザ情報を返す
	var m = map[string]interface{}{
		"sub":         user.sub,
		"name":        user.name_ja,
		"given_name":  user.given_name,
		"family_name": user.family_name,
		"locale":      user.locale,
	}
	buf, _ := json.MarshalIndent(m, "", "  ")
	w.WriteHeader(http.StatusOK)
	w.Write(buf)
}
