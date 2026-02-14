# 第12章: テストの書き方と動作確認

## テスト方針

認可サーバーのテストは以下の4レベルで行う。

| レベル | 対象 | ツール |
|-------|------|-------|
| ユニットテスト | 個別の関数・構造体 | `testing` パッケージ |
| ハンドラーテスト | HTTP エンドポイント | `net/http/httptest` |
| API 統合テスト | エンドポイント間のフロー | **runn** |
| Property Based Test | 入力空間の網羅的検証 | `testing/quick` (第13章) |

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
		Used:        true,
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

## 3. API 統合テスト (runn)

### runn とは

[runn](https://github.com/k1LoW/runn) はシナリオベースの API テストツールである。YAML でテストシナリオを宣言的に記述し、ステップ間で値を受け渡しながら複数の API コールを連鎖させることができる。

特徴:
- YAML による宣言的なシナリオ定義
- ステップ間の変数受け渡し（前のレスポンスを次のリクエストで使う）
- `go test` との統合（`RunN` による Go テスト実行）
- OpenAPI スキーマ検証との連携

### インストール

```bash
go install github.com/k1LoW/runn/cmd/runn@latest
```

### ディレクトリ構成

```
authz-server/
├── runbooks/
│   ├── client_credentials.yml       # Client Credentials フロー
│   ├── token_error_cases.yml        # トークンエンドポイントのエラーケース
│   ├── resource_server.yml          # リソースサーバーのアクセス制御
│   ├── refresh_token.yml            # リフレッシュトークンフロー
│   └── auth_code_with_pkce.yml      # Authorization Code + PKCE フロー
└── integration_test.go              # Go テストからの実行
```

### シナリオ 1: Client Credentials Grant

```yaml
# runbooks/client_credentials.yml
desc: "Client Credentials Grant でアクセストークンを取得する"
runners:
  authz: "http://localhost:8080"
  resource: "http://localhost:8081"
steps:
  # --- Step 1: Client Credentials でトークンを取得 ---
  - desc: "M2M クライアントでアクセストークンを取得"
    authz:
      /token:
        post:
          headers:
            Content-Type: "application/x-www-form-urlencoded"
            Authorization: "Basic bTJtLWNsaWVudDptMm0tc2VjcmV0"  # m2m-client:m2m-secret
          body:
            application/x-www-form-urlencoded:
              grant_type: "client_credentials"
              scope: "read:stats"
    test: |
      # ステータスコードの検証
      current.res.status == 200
      && current.res.headers["Content-Type"][0] == "application/json"
      # レスポンスボディの検証
      && current.res.body.token_type == "Bearer"
      && current.res.body.access_token != ""
      && current.res.body.expires_in == 3600
      && current.res.body.scope == "read:stats"
      # Client Credentials ではリフレッシュトークンは発行されない
      && current.res.body.refresh_token == null
    bind:
      access_token: current.res.body.access_token

  # --- Step 2: 取得したトークンでリソースサーバーにアクセス ---
  - desc: "公開エンドポイントにアクセス（トークン不要）"
    resource:
      /api/public:
        get: {}
    test: |
      current.res.status == 200
      && current.res.body.message == "this is a public endpoint"
```

### シナリオ 2: トークンエンドポイントのエラーケース

```yaml
# runbooks/token_error_cases.yml
desc: "トークンエンドポイントのエラーケースを網羅的にテストする"
runners:
  authz: "http://localhost:8080"
steps:
  # --- 不正なクライアント認証 ---
  - desc: "不正なクライアントシークレットで 401 が返る"
    authz:
      /token:
        post:
          headers:
            Content-Type: "application/x-www-form-urlencoded"
            Authorization: "Basic bTJtLWNsaWVudDp3cm9uZy1zZWNyZXQ="  # m2m-client:wrong-secret
          body:
            application/x-www-form-urlencoded:
              grant_type: "client_credentials"
    test: |
      current.res.status == 401
      && current.res.body.error == "invalid_client"

  # --- 存在しないクライアント ---
  - desc: "存在しないクライアントで 401 が返る"
    authz:
      /token:
        post:
          headers:
            Content-Type: "application/x-www-form-urlencoded"
            Authorization: "Basic bm9uZXhpc3RlbnQ6c2VjcmV0"  # nonexistent:secret
          body:
            application/x-www-form-urlencoded:
              grant_type: "client_credentials"
    test: |
      current.res.status == 401
      && current.res.body.error == "invalid_client"

  # --- サポートされていない grant_type ---
  - desc: "サポートされていない grant_type で 400 が返る"
    authz:
      /token:
        post:
          headers:
            Content-Type: "application/x-www-form-urlencoded"
          body:
            application/x-www-form-urlencoded:
              grant_type: "password"
              username: "testuser"
              password: "password"
    test: |
      current.res.status == 400
      && current.res.body.error == "unsupported_grant_type"

  # --- 許可されていない grant_type ---
  - desc: "Client Credentials 専用クライアントで authorization_code を使うと 400 が返る"
    authz:
      /token:
        post:
          headers:
            Content-Type: "application/x-www-form-urlencoded"
            Authorization: "Basic bTJtLWNsaWVudDptMm0tc2VjcmV0"  # m2m-client:m2m-secret
          body:
            application/x-www-form-urlencoded:
              grant_type: "authorization_code"
              code: "dummy-code"
    test: |
      current.res.status == 400
      && current.res.body.error == "unauthorized_client"

  # --- 不正な認可コード ---
  - desc: "存在しない認可コードで 400 が返る"
    authz:
      /token:
        post:
          headers:
            Content-Type: "application/x-www-form-urlencoded"
            Authorization: "Basic dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ="  # test-client:test-secret
          body:
            application/x-www-form-urlencoded:
              grant_type: "authorization_code"
              code: "nonexistent-code"
              redirect_uri: "http://localhost:3000/callback"
    test: |
      current.res.status == 400
      && current.res.body.error == "invalid_grant"

  # --- 不正なスコープ ---
  - desc: "許可されていないスコープで 400 が返る"
    authz:
      /token:
        post:
          headers:
            Content-Type: "application/x-www-form-urlencoded"
            Authorization: "Basic bTJtLWNsaWVudDptMm0tc2VjcmV0"  # m2m-client:m2m-secret
          body:
            application/x-www-form-urlencoded:
              grant_type: "client_credentials"
              scope: "read:profile delete:everything"
    test: |
      current.res.status == 400
      && current.res.body.error == "invalid_scope"
```

### シナリオ 3: リソースサーバーのアクセス制御

```yaml
# runbooks/resource_server.yml
desc: "リソースサーバーのアクセス制御を検証する"
runners:
  authz: "http://localhost:8080"
  resource: "http://localhost:8081"
steps:
  # --- トークンなしでアクセス → 401 ---
  - desc: "トークンなしで保護されたリソースにアクセスすると 401 が返る"
    resource:
      /api/profile:
        get: {}
    test: |
      current.res.status == 401

  # --- 不正なトークンでアクセス → 401 ---
  - desc: "不正なトークンで 401 が返る"
    resource:
      /api/profile:
        get:
          headers:
            Authorization: "Bearer invalid.token.value"
    test: |
      current.res.status == 401

  # --- 正規のトークンを取得してアクセス ---
  - desc: "Client Credentials でトークンを取得"
    authz:
      /token:
        post:
          headers:
            Content-Type: "application/x-www-form-urlencoded"
            Authorization: "Basic bTJtLWNsaWVudDptMm0tc2VjcmV0"
          body:
            application/x-www-form-urlencoded:
              grant_type: "client_credentials"
              scope: "read:stats"
    test: |
      current.res.status == 200
    bind:
      access_token: current.res.body.access_token

  # --- スコープ不足でアクセス → 403 ---
  - desc: "read:stats トークンで read:profile が必要なリソースにアクセスすると 403 が返る"
    resource:
      /api/profile:
        get:
          headers:
            Authorization: "Bearer {{ access_token }}"
    test: |
      current.res.status == 403
```

### シナリオ 4: リフレッシュトークンフロー

```yaml
# runbooks/refresh_token.yml
desc: "リフレッシュトークンのローテーションを検証する"
runners:
  authz: "http://localhost:8080"
vars:
  # テスト前にストアに認可コードを登録しておく前提
  # Go テスト側で httptest.Server を使う場合はそこで準備する
  test_auth_code: "test-refresh-flow-code"
steps:
  # --- Step 1: 認可コードでトークンを取得 ---
  - desc: "認可コードでアクセストークンとリフレッシュトークンを取得"
    authz:
      /token:
        post:
          headers:
            Content-Type: "application/x-www-form-urlencoded"
            Authorization: "Basic dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ="  # test-client:test-secret
          body:
            application/x-www-form-urlencoded:
              grant_type: "authorization_code"
              code: "{{ test_auth_code }}"
              redirect_uri: "http://localhost:3000/callback"
    test: |
      current.res.status == 200
      && current.res.body.access_token != ""
      && current.res.body.refresh_token != ""
    bind:
      access_token_1: current.res.body.access_token
      refresh_token_1: current.res.body.refresh_token

  # --- Step 2: リフレッシュトークンで新しいトークンを取得 ---
  - desc: "リフレッシュトークンでトークンを更新（ローテーション）"
    authz:
      /token:
        post:
          headers:
            Content-Type: "application/x-www-form-urlencoded"
            Authorization: "Basic dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ="
          body:
            application/x-www-form-urlencoded:
              grant_type: "refresh_token"
              refresh_token: "{{ refresh_token_1 }}"
    test: |
      current.res.status == 200
      && current.res.body.access_token != ""
      && current.res.body.refresh_token != ""
      # 新しいトークンが発行されている
      && current.res.body.access_token != "{{ access_token_1 }}"
      && current.res.body.refresh_token != "{{ refresh_token_1 }}"
    bind:
      access_token_2: current.res.body.access_token
      refresh_token_2: current.res.body.refresh_token

  # --- Step 3: 旧リフレッシュトークンが無効化されていることを確認 ---
  - desc: "旧リフレッシュトークンは使用できない（ローテーション検証）"
    authz:
      /token:
        post:
          headers:
            Content-Type: "application/x-www-form-urlencoded"
            Authorization: "Basic dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ="
          body:
            application/x-www-form-urlencoded:
              grant_type: "refresh_token"
              refresh_token: "{{ refresh_token_1 }}"
    test: |
      current.res.status == 400
      && current.res.body.error == "invalid_grant"
```

### シナリオ 5: Authorization Code + PKCE フロー

認可エンドポイントはブラウザのリダイレクトを伴うため、runn ではトークンエンドポイント側の PKCE 検証をテストする。認可コードはテスト前にストアに直接登録する。

```yaml
# runbooks/auth_code_with_pkce.yml
desc: "PKCE 付き Authorization Code Grant のトークン交換を検証する"
runners:
  authz: "http://localhost:8080"
vars:
  # テスト側で code_challenge = SHA256("test-code-verifier-12345678901234567890") のコードを登録
  code_verifier: "test-code-verifier-12345678901234567890"
  auth_code_with_pkce: "pkce-test-code"
steps:
  # --- 正常系: 正しい code_verifier ---
  - desc: "正しい code_verifier でトークン交換が成功する"
    authz:
      /token:
        post:
          headers:
            Content-Type: "application/x-www-form-urlencoded"
            Authorization: "Basic dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ="
          body:
            application/x-www-form-urlencoded:
              grant_type: "authorization_code"
              code: "{{ auth_code_with_pkce }}"
              redirect_uri: "http://localhost:3000/callback"
              code_verifier: "{{ code_verifier }}"
    test: |
      current.res.status == 200
      && current.res.body.access_token != ""
```

### Go テストからの runn 実行

runn のランブックを `go test` から実行する。テストサーバーをインプロセスで起動し、ランブックの接続先を動的に差し替える。

```go
// integration_test.go
//go:build integration

package main

import (
	"authz-server/internal/model"
	"authz-server/internal/pkce"
	"authz-server/internal/session"
	"authz-server/internal/store"
	"authz-server/internal/token"
	"authz-server/internal/handler"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/k1LoW/runn"
)

func TestRunbooks(t *testing.T) {
	// --- テストサーバーのセットアップ ---
	s := store.NewMemoryStore()
	store.Seed(s)
	issuer := token.NewJWTIssuer("test-secret-key-at-least-32-bytes!!", "http://test")
	sm := session.NewManager()

	authorizeHandler := handler.NewAuthorizeHandler(s, sm)
	tokenHandler := handler.NewTokenHandler(s, issuer)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", authorizeHandler.HandleAuthorize)
	mux.HandleFunc("POST /login", authorizeHandler.HandleLogin)
	mux.HandleFunc("POST /authorize", authorizeHandler.HandleConsent)
	mux.HandleFunc("POST /token", tokenHandler.HandleToken)

	authzServer := httptest.NewServer(mux)
	defer authzServer.Close()

	// リソースサーバー
	resourceMux := http.NewServeMux()
	resourceMux.Handle("GET /api/profile",
		middleware.RequireAuth(issuer, "read:profile")(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]string{
					"id": "user-1", "username": "testuser",
				})
			}),
		),
	)
	resourceMux.HandleFunc("GET /api/public", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"message": "this is a public endpoint"})
	})

	resourceServer := httptest.NewServer(resourceMux)
	defer resourceServer.Close()

	// --- テストデータの準備 ---

	// リフレッシュトークンテスト用の認可コード
	s.SaveAuthorizationCode(&model.AuthorizationCode{
		Code:        "test-refresh-flow-code",
		ClientID:    "test-client",
		UserID:      "user-1",
		RedirectURI: "http://localhost:3000/callback",
		Scope:       "read:profile",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	})

	// PKCE テスト用の認可コード
	codeVerifier := "test-code-verifier-12345678901234567890"
	codeChallenge := pkce.GenerateCodeChallenge(codeVerifier)
	s.SaveAuthorizationCode(&model.AuthorizationCode{
		Code:                "pkce-test-code",
		ClientID:            "test-client",
		UserID:              "user-1",
		RedirectURI:         "http://localhost:3000/callback",
		Scope:               "read:profile",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
	})

	// --- runn でランブックを実行 ---
	opts := []runn.Option{
		runn.T(t),
		runn.Runner("authz", authzServer.URL),     // YAML の authz を差し替え
		runn.Runner("resource", resourceServer.URL), // YAML の resource を差し替え
	}

	o, err := runn.Load("runbooks/**/*.yml", opts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.RunN(t.Context()); err != nil {
		t.Fatal(err)
	}
}
```

### 実行方法

```bash
# runn CLI で個別のランブック実行（サーバー起動済みの場合）
runn run runbooks/client_credentials.yml

# すべてのランブックを実行
runn run runbooks/*.yml

# go test 経由で実行（httptest を使うのでサーバー起動不要）
go test -tags integration -v -run TestRunbooks

# runn list でランブック一覧を確認
runn list runbooks/
```

### runn の主要機能まとめ

| 機能 | YAML での書き方 |
|------|---------------|
| 変数定義 | `vars:` セクション |
| 前ステップの値参照 | `{{ access_token }}` |
| レスポンス値のバインド | `bind:` で変数に格納 |
| アサーション | `test:` で CEL 式で記述 |
| HTTP ランナー | `runners:` で接続先を定義 |
| Go テスト連携 | `runn.T(t)` で `*testing.T` と統合 |
| ランナー差し替え | `runn.Runner("name", url)` で URL を動的に変更 |

### curl 手動テストとの比較

| 項目 | curl 手動テスト | runn |
|------|---------------|------|
| 再現性 | 低い（手で打つたびに異なる） | 高い（YAML で宣言的） |
| CI 統合 | スクリプト化が必要 | `go test` で実行可能 |
| ステップ間の値引き継ぎ | 変数に手動代入 | `bind:` で自動 |
| アサーション | `jq` で目視確認 | `test:` で自動検証 |
| エラーケース網羅 | 面倒 | YAML を並べるだけ |

## テスト実行

```bash
# ユニットテスト
go test ./internal/...

# 詳細出力
go test -v ./internal/...

# カバレッジ
go test -cover ./internal/...
go test -coverprofile=coverage.out ./internal/...
go tool cover -html=coverage.out

# 統合テスト (runn)
go test -tags integration -v -run TestRunbooks
```

## エラーケースのテスト一覧

必ずテストすべきエラーケース:

| エンドポイント | ケース | テスト種別 |
|--------------|--------|-----------|
| `/authorize` | 不正な `client_id` | ハンドラーテスト |
| `/authorize` | 不正な `redirect_uri` | ハンドラーテスト |
| `/authorize` | 不正な `response_type` | ハンドラーテスト |
| `/authorize` | スコープ超過 | ハンドラーテスト |
| `/token` | 不正なクライアント認証 | runn |
| `/token` | 期限切れの認可コード | ハンドラーテスト |
| `/token` | 使用済みの認可コード | runn / ハンドラー |
| `/token` | client_id 不一致 | ハンドラーテスト |
| `/token` | redirect_uri 不一致 | ハンドラーテスト |
| `/token` | PKCE 検証失敗 | runn |
| `/token` | 無効なリフレッシュトークン | runn |
| `/token` | 無効化されたリフレッシュトークン | runn |
| `/token` | サポートされていない grant_type | runn |
| Resource API | トークンなし → 401 | runn |
| Resource API | 期限切れトークン → 401 | ハンドラーテスト |
| Resource API | スコープ不足 → 403 | runn |

## 次章

[第13章: Property Based Testing](./13-property-based-testing.md) で、ランダム入力を使った網羅的なテスト手法を学ぶ。
