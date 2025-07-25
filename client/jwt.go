package main

import (
	"bytes"
	"crypto/sha256"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt"

	//"crypto"
	"crypto/rsa"
	//"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
)

type JwtData struct {
	header_payload string
	header         map[string]any
	header_raw     string
	payLoad        map[string]any
	payLoad_raw    string
	signature      []byte
}

func base64URLEncode(str string) string {
	hash := sha256.Sum256([]byte(str))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func fillB64Length(jwt string) (b64 string) {
	replace := strings.NewReplacer("-", "+", "_", "/")
	b64 = replace.Replace(jwt)

	if len(jwt)%4 != 0 {
		addLength := len(jwt) % 4
		for i := 0; i < addLength; i++ {
			b64 += "="
		}
	}

	return b64
}

func decodeJWT(idToken string) (jwtdata JwtData) {
	tmp := strings.Split(idToken, ".")
	jwtdata.header_payload = fmt.Sprintf("%s.%s", tmp[0], tmp[1])
	jwtdata.header_raw = tmp[0]
	jwtdata.payLoad_raw = tmp[1]

	header := fillB64Length(tmp[0])
	payload := fillB64Length(tmp[1])

	decHeader, _ := base64.StdEncoding.DecodeString(header)
	decPayload, _ := base64.StdEncoding.DecodeString(payload)
	decSignature, err := base64.RawURLEncoding.DecodeString(tmp[2])
	if err != nil {
		log.Println(err)
	}
	jwtdata.signature = decSignature

	json.NewDecoder(bytes.NewReader(decHeader)).Decode(&jwtdata.header)
	json.NewDecoder(bytes.NewReader(decPayload)).Decode(&jwtdata.payLoad)

	return jwtdata
}

func verifyJWTSignature(jwtdata JwtData, id_token string, oidc oidc) error {

	pubkey := rsa.PublicKey{}
	var keyList map[string]interface{}

	req, err := http.NewRequest("GET", oidc.keyEndpoint, nil)
	if err != nil {
		return fmt.Errorf("http request err : %s", err)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http client err : %s", err)
	}
	defer resp.Body.Close()
	json.NewDecoder(resp.Body).Decode(&keyList)

	for _, val := range keyList["keys"].([]interface{}) {
		key := val.(map[string]interface{})
		if key["kid"] == jwtdata.header["kid"].(string) {
			number, _ := base64.RawURLEncoding.DecodeString(key["n"].(string))
			pubkey.N = new(big.Int).SetBytes(number)
			pubkey.E = 65537
		}
	}

	hasher := sha256.New()
	hasher.Write([]byte(jwtdata.header_payload))

	// 標準pkgの機能で署名検証
	/*err = rsa.VerifyPKCS1v15(&pubkey, crypto.SHA256, hasher.Sum(nil), jwtdata.signature)
	if err != nil {
		return fmt.Errorf("Verify err : %s\n", err)
	} else {
		log.Println("Verify success by VerifyPKCS1v15!!")
	}*/

	derRsaPubKey, err := x509.MarshalPKIXPublicKey(&pubkey)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: derRsaPubKey})
	if err != nil {
		return err
	}

	// golang-jwtライブラリで署名検証
	// https://github.com/golang-jwt/jwt/blob/main/cmd/jwt/main.go
	token, err := jwt.Parse(id_token, func(token *jwt.Token) (interface{}, error) {
		return jwt.ParseRSAPublicKeyFromPEM(buf.Bytes())
	})
	if err != nil {
		log.Printf("couldn't parse token: %s \n", err)
	}
	if !token.Valid {
		log.Println("token is invalid")
	} else {
		log.Println("token is valid!!")
	}
	return nil
}

func verifyJWT(tokenString string) {

	data, err := os.ReadFile("../goauth-server/public-key.pem")
	if err != nil {
		log.Printf("read pub key is err : %s\n", err)
		os.Exit(1)
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(data)
	if err != nil {
		log.Printf("parse private key err : %s\n", err)
		os.Exit(1)
	}
	_ = key

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwt.ParseRSAPublicKeyFromPEM(data)
	})
	if err != nil {
		log.Printf("verifyJWT validate: %s\n", err)
		//os.Exit(1)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		log.Printf("verifyJWT invalid: %s\n", err)
		//os.Exit(1)
	}
	if token.Valid {
		log.Println("verifyJWT : token is 正しい!!!")
	}

	buf, _ := json.Marshal(claims)
	_ = buf

}

func verifyToken(data JwtData, access_token string, oidc oidc) error {

	// トークン発行元の確認
	if oidc.iss != data.payLoad["iss"].(string) {
		return fmt.Errorf("iss not match")
	}
	// クライアントIDの確認
	if oidc.clientId != data.payLoad["aud"].(string) {
		return fmt.Errorf("acoount_id not match")
	}
	// nonceの確認
	if oidc.nonce != data.payLoad["nonce"].(string) {
		return fmt.Errorf("nonce is not match")
	}
	// IDトークンの有効期限を期限を確認
	now := time.Now().Unix()
	if data.payLoad["exp"].(float64) < float64(now) {
		return fmt.Errorf("token time limit expired")
	}
	// at_hashのチェック
	//token_athash := base64URLEncode(access_token)
	//if token_athash[0:21] != data.payLoad["at_hash"].(string)[0:21] {
	//	return fmt.Errorf("at_hash not match")
	//}

	return nil
}
