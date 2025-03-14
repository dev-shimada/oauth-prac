package jwt

import (
	"encoding/json"
	"os"

	"github.com/lestrrat-go/jwx/jwk"
)

// 　JWKを作成してJSONにして返す
func MakeJWK() []byte {

	data, _ := os.ReadFile("jwt-public.pem")
	keyset, _ := jwk.ParseKey(data, jwk.WithPEM(true))

	keyset.Set(jwk.KeyIDKey, "12345678")
	keyset.Set(jwk.AlgorithmKey, "RS256")
	keyset.Set(jwk.KeyUsageKey, "sig")

	jwk := map[string]interface{}{
		"keys": []interface{}{keyset},
	}
	buf, _ := json.MarshalIndent(jwk, "", "  ")
	return buf
}
