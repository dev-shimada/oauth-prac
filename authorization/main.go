package main

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})
	mux.HandleFunc("/auth", auth)

	// Wait here until CTRL+C or other term signal is received
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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

var sessionList = make(map[string]Session)

func auth(w http.ResponseWriter, req *http.Request) {

	sessionId := uuid.New().String()
	// セッションを保存しておく
	session := Session{
		client: "client_id",
		scopes: "scope",
	}
	sessionList[sessionId] = session

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
