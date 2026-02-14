# 第12章: テストの書き方と動作確認

## テスト方針

認可サーバーのテストは以下の3レベルで行う。

| レベル | 対象 | ツール |
|-------|------|-------|
| ユニットテスト | 個別の関数・構造体 | `testing` パッケージ |
| ハンドラーテスト | HTTP エンドポイント | `net/http/httptest` |
| 統合テスト | 全フロー通し | `net/http/httptest` + curl |

## 1. ユニットテスト

### JWT トークンのテスト

```go
// internal/token/jwt_test.go
package token

import (
	"testing"
	"time"
)

func TestGenerateAndVerifyAccessToken(t *testing.T) {
	issuer := NewJWTIssuer("test-secret-key-at-least-32-bytes!!", "http://test-issuer")

	tokenStr, err := issuer.GenerateAccessToken("user-1", "client-1", "read:profile")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	if tokenStr == "" {
		t.Fatal("token should not be empty")
	}

	// トークンの検証
	claims, err := issuer.VerifyAccessToken(tokenStr)
	if err != nil {
		t.Fatalf("failed to verify token: %v", err)
	}

	if claims.Subject != "user-1" {
		t.Errorf("subject: got %q, want %q", claims.Subject, "user-1")
	}

	if claims.ClientID != "client-1" {
		t.Errorf("client_id: got %q, want %q", claims.ClientID, "client-1")
	}

	if claims.Scope != "read:profile" {
		t.Errorf("scope: got %q, want %q", claims.Scope, "read:profile")
	}

	if claims.Issuer != "http://test-issuer" {
		t.Errorf("issuer: got %q, want %q", claims.Issuer, "http://test-issuer")
	}
}

func TestVerifyAccessToken_InvalidSignature(t *testing.T) {
	issuer1 := NewJWTIssuer("secret-key-1-at-least-32-bytes!!!", "http://test-issuer")
	issuer2 := NewJWTIssuer("secret-key-2-at-least-32-bytes!!!", "http://test-issuer")

	// issuer1 で発行したトークンを issuer2 で検証
	tokenStr, _ := issuer1.GenerateAccessToken("user-1", "client-1", "read:profile")
	_, err := issuer2.VerifyAccessToken(tokenStr)

	if err == nil {
		t.Error("expected error for invalid signature, got nil")
	}
}

func TestVerifyAccessToken_Expired(t *testing.T) {
	issuer := NewJWTIssuer("test-secret-key-at-least-32-bytes!!", "http://test-issuer")

	// 期限切れのトークンを手動生成
	claims := Claims{
		Issuer:    "http://test-issuer",
		Subject:   "user-1",
		ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(), // 1時間前に期限切れ
		IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
		ClientID:  "client-1",
		Scope:     "read:profile",
	}

	tokenStr, _ := issuer.sign(claims)
	_, err := issuer.VerifyAccessToken(tokenStr)

	if err != ErrExpiredToken {
		t.Errorf("expected ErrExpiredToken, got %v", err)
	}
}

func TestVerifyAccessToken_MalformedToken(t *testing.T) {
	issuer := NewJWTIssuer("test-secret-key-at-least-32-bytes!!", "http://test-issuer")

	testCases := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no dots", "nodots"},
		{"one dot", "one.dot"},
		{"random string", "abc.def.ghi"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := issuer.VerifyAccessToken(tc.token)
			if err == nil {
				t.Errorf("expected error for malformed token %q, got nil", tc.token)
			}
		})
	}
}
```

### PKCE のテスト

```go
// internal/pkce/pkce_test.go
package pkce

import "testing"

func TestVerifyS256(t *testing.T) {
	// RFC 7636 Appendix B の例
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := GenerateCodeChallenge(codeVerifier)

	if !Verify(codeVerifier, codeChallenge, "S256") {
		t.Error("S256 verification should succeed")
	}
}

func TestVerifyS256_WrongVerifier(t *testing.T) {
	codeVerifier := "correct-verifier-value"
	codeChallenge := GenerateCodeChallenge(codeVerifier)

	if Verify("wrong-verifier", codeChallenge, "S256") {
		t.Error("S256 verification should fail with wrong verifier")
	}
}

func TestVerifyPlain(t *testing.T) {
	codeVerifier := "my-code-verifier"

	if !Verify(codeVerifier, codeVerifier, "plain") {
		t.Error("plain verification should succeed when verifier equals challenge")
	}
}

func TestVerifyPlain_Mismatch(t *testing.T) {
	if Verify("verifier", "different", "plain") {
		t.Error("plain verification should fail when verifier differs from challenge")
	}
}

func TestVerify_EmptyInputs(t *testing.T) {
	if Verify("", "challenge", "S256") {
		t.Error("should fail with empty verifier")
	}
	if Verify("verifier", "", "S256") {
		t.Error("should fail with empty challenge")
	}
}

func TestVerify_UnsupportedMethod(t *testing.T) {
	if Verify("verifier", "challenge", "unsupported") {
		t.Error("should fail with unsupported method")
	}
}
```

### スコープ検証のテスト

```go
// internal/auth/scope_test.go
package auth

import "testing"

func TestScopeContains(t *testing.T) {
	allowed := []string{"read:profile", "write:profile", "read:posts"}

	testCases := []struct {
		name      string
		requested string
		want      bool
	}{
		{"single valid scope", "read:profile", true},
		{"multiple valid scopes", "read:profile write:profile", true},
		{"all scopes", "read:profile write:profile read:posts", true},
		{"invalid scope", "delete:profile", false},
		{"mix of valid and invalid", "read:profile delete:profile", false},
		{"empty scope", "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ScopeContains(allowed, tc.requested)
			if got != tc.want {
				t.Errorf("ScopeContains(%v, %q) = %v, want %v",
					allowed, tc.requested, got, tc.want)
			}
		})
	}
}
```

## 2. ハンドラーテスト

`net/http/httptest` を使ってHTTPハンドラーをテストする。

### トークンエンドポイントのテスト

```go
// internal/handler/token_test.go
package handler

import (
	"authz-server/internal/model"
	"authz-server/internal/store"
	"authz-server/internal/token"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func setupTokenTest() (*TokenHandler, store.Store) {
	s := store.NewMemoryStore()
	store.Seed(s)
	issuer := token.NewJWTIssuer("test-secret-key-at-least-32-bytes!!", "http://test")
	handler := NewTokenHandler(s, issuer)
	return handler, s
}

func TestTokenEndpoint_ClientCredentials(t *testing.T) {
	handler, _ := setupTokenTest()

	body := "grant_type=client_credentials&scope=read:stats"
	req := httptest.NewRequest("POST", "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("m2m-client:m2m-secret")))

	w := httptest.NewRecorder()
	handler.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d. body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp model.TokenResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.AccessToken == "" {
		t.Error("access_token should not be empty")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type: got %q, want %q", resp.TokenType, "Bearer")
	}
	if resp.RefreshToken != "" {
		t.Error("client_credentials should not return refresh_token")
	}

	// Cache-Control ヘッダーの検証
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("Cache-Control should be no-store")
	}
}

func TestTokenEndpoint_InvalidClient(t *testing.T) {
	handler, _ := setupTokenTest()

	body := "grant_type=client_credentials"
	req := httptest.NewRequest("POST", "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("wrong:wrong")))

	w := httptest.NewRecorder()
	handler.HandleToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}

	var resp model.ErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.Error != "invalid_client" {
		t.Errorf("error: got %q, want %q", resp.Error, "invalid_client")
	}
}

func TestTokenEndpoint_AuthorizationCode(t *testing.T) {
	handler, s := setupTokenTest()

	// テスト用の認可コードを発行
	authCode := &model.AuthorizationCode{
		Code:        "test-auth-code",
		ClientID:    "test-client",
		UserID:      "user-1",
		RedirectURI: "http://localhost:3000/callback",
		Scope:       "read:profile",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		Used:        false,
	}
	s.SaveAuthorizationCode(authCode)

	body := "grant_type=authorization_code&code=test-auth-code&redirect_uri=http://localhost:3000/callback"
	req := httptest.NewRequest("POST", "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("test-client:test-secret")))

	w := httptest.NewRecorder()
	handler.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d. body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp model.TokenResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.AccessToken == "" {
		t.Error("access_token should not be empty")
	}
	if resp.RefreshToken == "" {
		t.Error("refresh_token should not be empty")
	}
}

func TestTokenEndpoint_AuthorizationCode_UsedCode(t *testing.T) {
	handler, s := setupTokenTest()

	authCode := &model.AuthorizationCode{
		Code:        "used-code",
		ClientID:    "test-client",
		UserID:      "user-1",
		RedirectURI: "http://localhost:3000/callback",
		Scope:       "read:profile",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		Used:        true, // 使用済み
	}
	s.SaveAuthorizationCode(authCode)

	body := "grant_type=authorization_code&code=used-code&redirect_uri=http://localhost:3000/callback"
	req := httptest.NewRequest("POST", "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("test-client:test-secret")))

	w := httptest.NewRecorder()
	handler.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp model.ErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.Error != "invalid_grant" {
		t.Errorf("error: got %q, want %q", resp.Error, "invalid_grant")
	}
}

func TestTokenEndpoint_UnsupportedGrantType(t *testing.T) {
	handler, _ := setupTokenTest()

	body := "grant_type=password&username=test&password=test"
	req := httptest.NewRequest("POST", "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	handler.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp model.ErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.Error != "unsupported_grant_type" {
		t.Errorf("error: got %q, want %q", resp.Error, "unsupported_grant_type")
	}
}
```

### リソースサーバーのテスト

```go
// internal/middleware/middleware_test.go
package middleware

import (
	"authz-server/internal/token"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireAuth_ValidToken(t *testing.T) {
	issuer := token.NewJWTIssuer("test-secret-key-at-least-32-bytes!!", "http://test")
	tokenStr, _ := issuer.GenerateAccessToken("user-1", "client-1", "read:profile")

	handler := RequireAuth(issuer, "read:profile")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r)
			if claims == nil {
				t.Error("claims should not be nil")
			}
			if claims.Subject != "user-1" {
				t.Errorf("subject: got %q, want %q", claims.Subject, "user-1")
			}
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest("GET", "/api/profile", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRequireAuth_MissingToken(t *testing.T) {
	issuer := token.NewJWTIssuer("test-secret-key-at-least-32-bytes!!", "http://test")

	handler := RequireAuth(issuer, "read:profile")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("handler should not be called")
		}),
	)

	req := httptest.NewRequest("GET", "/api/profile", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestRequireAuth_InsufficientScope(t *testing.T) {
	issuer := token.NewJWTIssuer("test-secret-key-at-least-32-bytes!!", "http://test")
	tokenStr, _ := issuer.GenerateAccessToken("user-1", "client-1", "read:profile")

	// write:profile を要求するが、トークンには read:profile しかない
	handler := RequireAuth(issuer, "write:profile")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("handler should not be called")
		}),
	)

	req := httptest.NewRequest("GET", "/api/profile", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusForbidden)
	}
}
```

## 3. 統合テスト (手動)

すべてのコンポーネントを起動して、フロー全体を通してテストする。

### セットアップ

```bash
# ターミナル 1: 認可サーバー
JWT_SECRET_KEY="super-secret-key-at-least-32-bytes!!" go run main.go
# => Authorization Server listening on :8080

# ターミナル 2: リソースサーバー
JWT_SECRET_KEY="super-secret-key-at-least-32-bytes!!" go run resource-server/main.go
# => Resource Server listening on :8081
```

### テストフロー: Authorization Code Grant + PKCE

```bash
# Step 1: PKCE パラメータの準備
CODE_VERIFIER=$(openssl rand -hex 32)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
echo "Verifier: $CODE_VERIFIER"
echo "Challenge: $CODE_CHALLENGE"

# Step 2: ブラウザで認可リクエストを開く
open "http://localhost:8080/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:3000/callback&scope=read:profile&state=test-state&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256"

# Step 3: ログイン画面で認証
#   Username: testuser
#   Password: password

# Step 4: 同意画面で「許可する」をクリック
# → http://localhost:3000/callback?code=xxxx&state=test-state にリダイレクトされる
# ブラウザのアドレスバーから code= の値をコピー

# Step 5: トークン交換
AUTH_CODE="<コピーした認可コード>"
curl -s -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "test-client:test-secret" \
  -d "grant_type=authorization_code" \
  -d "code=${AUTH_CODE}" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "code_verifier=${CODE_VERIFIER}" | jq .

# レスポンス例:
# {
#   "access_token": "eyJhbGciOiJIUzI1NiIs...",
#   "token_type": "Bearer",
#   "expires_in": 3600,
#   "refresh_token": "a1b2c3d4...",
#   "scope": "read:profile"
# }

# Step 6: アクセストークンでリソースにアクセス
ACCESS_TOKEN="<取得したアクセストークン>"
curl -s http://localhost:8081/api/profile \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" | jq .

# レスポンス例:
# {
#   "id": "user-1",
#   "username": "testuser",
#   "email": "testuser@example.com"
# }

# Step 7: リフレッシュトークンでトークンを更新
REFRESH_TOKEN="<取得したリフレッシュトークン>"
curl -s -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "test-client:test-secret" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=${REFRESH_TOKEN}" | jq .
```

### テストフロー: Client Credentials Grant

```bash
curl -s -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "m2m-client:m2m-secret" \
  -d "grant_type=client_credentials&scope=read:stats" | jq .
```

## テスト実行

```bash
# 全テスト実行
go test ./...

# 特定パッケージのテスト
go test ./internal/token/
go test ./internal/pkce/
go test ./internal/handler/

# 詳細出力
go test -v ./...

# カバレッジ
go test -cover ./...
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## エラーケースのテスト一覧

必ずテストすべきエラーケース:

| エンドポイント | ケース |
|--------------|--------|
| `/authorize` | 不正な `client_id` |
| `/authorize` | 不正な `redirect_uri` |
| `/authorize` | 不正な `response_type` |
| `/authorize` | スコープ超過 |
| `/token` | 不正なクライアント認証 |
| `/token` | 期限切れの認可コード |
| `/token` | 使用済みの認可コード |
| `/token` | client_id 不一致 |
| `/token` | redirect_uri 不一致 |
| `/token` | PKCE 検証失敗 |
| `/token` | 無効なリフレッシュトークン |
| `/token` | 無効化されたリフレッシュトークン |
| `/token` | サポートされていない grant_type |
| Resource API | トークンなし → 401 |
| Resource API | 期限切れトークン → 401 |
| Resource API | スコープ不足 → 403 |

## まとめ

本教材では、OAuth 2.0 認可サーバーを Go の標準ライブラリだけで実装した。以下のコンポーネントを作成した：

1. **データモデル** — Client, AuthorizationCode, Token 等の構造体
2. **インメモリストア** — スレッドセーフなデータストア
3. **認可エンドポイント** — ログイン画面、同意画面、認可コード発行
4. **トークンエンドポイント** — 3種類のグラントタイプに対応
5. **JWT** — HMAC-SHA256 による署名・検証
6. **リソースサーバー** — Bearer トークン検証ミドルウェア
7. **PKCE** — 認可コード横取り攻撃の対策
8. **リフレッシュトークン** — トークンローテーション
9. **セキュリティ対策** — CSRF, レート制限, ロギング

### 本番環境に向けて追加すべきこと

- データベース (PostgreSQL 等) への移行
- HTTPS の強制
- クライアントシークレットの bcrypt ハッシュ化
- トークンの失効管理 (Revocation Endpoint, RFC 7009)
- トークンイントロスペクション (RFC 7662)
- Dynamic Client Registration (RFC 7591)
- OpenID Connect 対応 (ID Token の発行)

### 参考 RFC 一覧

| RFC | タイトル |
|-----|---------|
| RFC 6749 | The OAuth 2.0 Authorization Framework |
| RFC 6750 | Bearer Token Usage |
| RFC 6819 | OAuth 2.0 Threat Model and Security Considerations |
| RFC 7519 | JSON Web Token (JWT) |
| RFC 7636 | Proof Key for Code Exchange (PKCE) |
| RFC 7009 | OAuth 2.0 Token Revocation |
| RFC 7662 | OAuth 2.0 Token Introspection |
