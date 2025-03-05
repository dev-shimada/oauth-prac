package main

import (
	"net/http"
	"net/url"
	"time"
)

// 認可サーバーの認可エンドポイントのHTTP Handler
func (as *AuthorizationServer) AuthorizeEndpoint(w http.ResponseWriter, r *http.Request) {
	// 必須のパラメーターを取得
	responseType := r.URL.Query().Get("response_type")
	clientID := r.URL.Query().Get("client_id")
	redirectUri := r.URL.Query().Get("redirect_uri")

	// 今回は認可コードフローのみをサポート
	if responseType != "code" {
		http.Error(w, "Invalid response_type", http.StatusBadRequest)
		return
	}

	// 事前にクライアントに設定されているリダイレクトURIと一致するか確認する
	client, exists := as.GetClient(ClientID(clientID))
	if !exists {
		http.Error(w, "Invalid client_id", http.StatusUnauthorized)
		return
	}
	if client.RedirectUri != redirectUri {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	// 認可コードを生成する
	code := as.generateAuthorizationCode(client, r.URL.Query().Get("redirect_uri"))

	// リダイレクトURIのクエリパラメーターに認可コードを付与してユーザーエージェントにリダイレクト
	params := url.Values{"code": {code.Code.String()}}
	redirectUri += "?" + params.Encode()
	http.Redirect(w, r, redirectUri, http.StatusFound)
}

// 認可コードを生成し、認可コード情報をサーバーに保存する
func (as *AuthorizationServer) generateAuthorizationCode(client *ConfidentialClient, redirectUri string) *authorizationCodeInfo {
	aci := &authorizationCodeInfo{
		Code:        uuid.New().String(),
		ClientID:    client.ID,
		RedirectUri: redirectUri,
		ExpiresAt:   time.Now().Add(time.Minute * 10).Unix(),
	}
	as.authorizationCodeInfos[aci.Code] = aci
	return aci
}

// 生成されている認可コード情報を取得する
func (as *AuthorizationServer) getAuthorizationCodeInfo(code string) (*authorizationCodeInfo, bool) {
	aci, exists := as.authorizationCodeInfos[code]
	return aci, exists
}

// サーバーで保持するための、認可コード情報
type authorizationCodeInfo struct {
	Code        string   // 認可コード
	ClientID    ClientID // 紐づくクライアントID
	RedirectUri string   // リダイレクトURI
	ExpiresAt   int64    // 有効期限（UNIXタイムスタンプ）
}

func (aci *authorizationCodeInfo) Validate(code string, clientID ClientID) bool {
	// 認可コードが一致し、かつクライアントIDが一致し、かつ有効期限が切れていない
	return aci.Code == code && aci.ClientID == clientID && time.Now().Unix() < aci.ExpiresAt
}
