package main

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
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

	// Wait here until CTRL+C or other term signal is received
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:    "8080",
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
	var sessionList = make(map[string]Session)
	sessionList[sessionId] = session

	// CookieにセッションIDをセット
	cookie := &http.Cookie{
		Name:  "session",
		Value: sessionId,
	}
	http.SetCookie(w, cookie)

	// ログイン&権限認可の画面を戻す
	var templates = make(map[string]*template.Template)
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

		var sessionList = make(map[string]Session)
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
		var AuthCodeList = make(map[string]AuthCode)
		AuthCodeList[authCodeString] = authData

		log.Printf("auth code accepet : %v\n", authData)

		location := fmt.Sprintf("%s?code=%s&state=%s", v.redirectUri, authCodeString, v.state)
		w.Header().Add("Location", location)
		w.WriteHeader(302)

	}

}
