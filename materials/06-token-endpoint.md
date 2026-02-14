# 第6章: トークンエンドポイントの実装

## トークンエンドポイントの役割

`/token` はクライアントがサーバー間通信 (バックチャネル) で呼び出すエンドポイントである。以下のグラントタイプを処理する。

- `authorization_code` — 認可コードをトークンに交換
- `client_credentials` — クライアント認証のみでトークン発行
- `refresh_token` — リフレッシュトークンでアクセストークンを再発行

## 基本仕様

- HTTP メソッド: **POST のみ**
- Content-Type: `application/x-www-form-urlencoded`
- レスポンス: `application/json`
- クライアント認証: Basic 認証 または POST ボディの `client_id` / `client_secret`

## ハンドラーの実装

```go
// internal/handler/token.go
package handler

import (
	"authz-server/internal/auth"
	"authz-server/internal/model"
	"authz-server/internal/pkce"
	"authz-server/internal/store"
	"authz-server/internal/token"
	"encoding/json"
	"net/http"
	"time"
)

// TokenHandler はトークンエンドポイントを処理する。
type TokenHandler struct {
	store     store.Store
	jwtIssuer *token.JWTIssuer
}

// NewTokenHandler は新しい TokenHandler を返す。
func NewTokenHandler(s store.Store, issuer *token.JWTIssuer) *TokenHandler {
	return &TokenHandler{
		store:     s,
		jwtIssuer: issuer,
	}
}

// HandleToken は POST /token を処理する。
// RFC 6749 Section 3.2 に対応。
func (h *TokenHandler) HandleToken(w http.ResponseWriter, r *http.Request) {
	// Content-Type の検証
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		tokenError(w, http.StatusBadRequest, "invalid_request",
			"Content-Type must be application/x-www-form-urlencoded")
		return
	}

	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "failed to parse form")
		return
	}

	grantType := r.FormValue("grant_type")

	switch grantType {
	case model.GrantTypeAuthorizationCode:
		h.handleAuthorizationCodeGrant(w, r)
	case model.GrantTypeClientCredentials:
		h.handleClientCredentialsGrant(w, r)
	case model.GrantTypeRefreshToken:
		h.handleRefreshTokenGrant(w, r)
	default:
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type",
			"grant_type must be authorization_code, client_credentials, or refresh_token")
	}
}
```

## Authorization Code Grant の処理

```go
// handleAuthorizationCodeGrant は認可コードグラントを処理する。
// RFC 6749 Section 4.1.3 に対応。
func (h *TokenHandler) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	// --- Step 1: クライアント認証 ---
	client, err := auth.AuthenticateClient(r, h.store)
	if err != nil {
		tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	// grant_type が許可されているか
	if !containsString(client.GrantTypes, model.GrantTypeAuthorizationCode) {
		tokenError(w, http.StatusBadRequest, "unauthorized_client",
			"this client is not authorized for authorization_code grant")
		return
	}

	// --- Step 2: 認可コードの検証 ---
	code := r.FormValue("code")
	if code == "" {
		tokenError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}

	authCode, err := h.store.GetAuthorizationCode(code)
	if err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "authorization code not found")
		return
	}

	// 認可コードが使用済みでないか
	if authCode.Used {
		// RFC 6749 Section 4.1.2:
		// 認可コードが複数回使用された場合、その認可コードに基づいて
		// 発行されたすべてのトークンを無効化すべき (SHOULD)
		h.store.DeleteAuthorizationCode(code)
		tokenError(w, http.StatusBadRequest, "invalid_grant",
			"authorization code has already been used")
		return
	}

	// 有効期限の検証
	if time.Now().After(authCode.ExpiresAt) {
		h.store.DeleteAuthorizationCode(code)
		tokenError(w, http.StatusBadRequest, "invalid_grant",
			"authorization code has expired")
		return
	}

	// client_id の一致検証
	if authCode.ClientID != client.ID {
		tokenError(w, http.StatusBadRequest, "invalid_grant",
			"authorization code was not issued to this client")
		return
	}

	// redirect_uri の一致検証
	redirectURI := r.FormValue("redirect_uri")
	if authCode.RedirectURI != "" && redirectURI != authCode.RedirectURI {
		tokenError(w, http.StatusBadRequest, "invalid_grant",
			"redirect_uri does not match the one used in authorization request")
		return
	}

	// --- Step 3: PKCE 検証（第9章で詳細解説） ---
	if authCode.CodeChallenge != "" {
		codeVerifier := r.FormValue("code_verifier")
		if codeVerifier == "" {
			tokenError(w, http.StatusBadRequest, "invalid_request",
				"code_verifier is required")
			return
		}
		if !pkce.Verify(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			tokenError(w, http.StatusBadRequest, "invalid_grant",
				"code_verifier verification failed")
			return
		}
	}

	// --- Step 4: 認可コードを使用済みにする ---
	authCode.Used = true

	// --- Step 5: トークンの発行 ---
	accessToken, err := h.jwtIssuer.GenerateAccessToken(authCode.UserID, authCode.ClientID, authCode.Scope)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error",
			"failed to generate access token")
		return
	}

	// リフレッシュトークンの生成
	refreshTokenStr, err := auth.GenerateRandomString(32)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error",
			"failed to generate refresh token")
		return
	}

	refreshToken := &model.RefreshToken{
		Token:     refreshTokenStr,
		ClientID:  client.ID,
		UserID:    authCode.UserID,
		Scope:     authCode.Scope,
		ExpiresAt: time.Now().Add(model.RefreshTokenLifetime),
		Revoked:   false,
	}

	if err := h.store.SaveRefreshToken(refreshToken); err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error",
			"failed to save refresh token")
		return
	}

	// --- Step 6: レスポンスの送信 ---
	resp := model.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(model.AccessTokenLifetime.Seconds()),
		RefreshToken: refreshTokenStr,
		Scope:        authCode.Scope,
	}

	tokenResponse(w, resp)
}
```

## Client Credentials Grant の処理

```go
// handleClientCredentialsGrant はクライアントクレデンシャルグラントを処理する。
// RFC 6749 Section 4.4 に対応。
func (h *TokenHandler) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	// --- Step 1: クライアント認証 ---
	client, err := auth.AuthenticateClient(r, h.store)
	if err != nil {
		tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	if !containsString(client.GrantTypes, model.GrantTypeClientCredentials) {
		tokenError(w, http.StatusBadRequest, "unauthorized_client",
			"this client is not authorized for client_credentials grant")
		return
	}

	// --- Step 2: スコープの検証 ---
	scope := r.FormValue("scope")
	if scope != "" && !auth.ScopeContains(client.Scopes, scope) {
		tokenError(w, http.StatusBadRequest, "invalid_scope",
			"requested scope exceeds client's allowed scopes")
		return
	}

	if scope == "" {
		// スコープ未指定時はクライアントのデフォルトスコープを使用
		scope = joinScopes(client.Scopes)
	}

	// --- Step 3: アクセストークンの発行 ---
	// Client Credentials ではユーザーは存在しない
	accessToken, err := h.jwtIssuer.GenerateAccessToken("", client.ID, scope)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error",
			"failed to generate access token")
		return
	}

	// RFC 6749 Section 4.4.3:
	// Client Credentials Grant ではリフレッシュトークンを発行すべきでない
	resp := model.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(model.AccessTokenLifetime.Seconds()),
		Scope:       scope,
	}

	tokenResponse(w, resp)
}
```

## Refresh Token Grant の処理

```go
// handleRefreshTokenGrant はリフレッシュトークングラントを処理する。
// RFC 6749 Section 6 に対応。
func (h *TokenHandler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	// --- Step 1: クライアント認証 ---
	client, err := auth.AuthenticateClient(r, h.store)
	if err != nil {
		tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	if !containsString(client.GrantTypes, model.GrantTypeRefreshToken) {
		tokenError(w, http.StatusBadRequest, "unauthorized_client",
			"this client is not authorized for refresh_token grant")
		return
	}

	// --- Step 2: リフレッシュトークンの検証 ---
	refreshTokenStr := r.FormValue("refresh_token")
	if refreshTokenStr == "" {
		tokenError(w, http.StatusBadRequest, "invalid_request",
			"refresh_token is required")
		return
	}

	refreshToken, err := h.store.GetRefreshToken(refreshTokenStr)
	if err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_grant",
			"refresh token not found")
		return
	}

	if refreshToken.Revoked {
		tokenError(w, http.StatusBadRequest, "invalid_grant",
			"refresh token has been revoked")
		return
	}

	if time.Now().After(refreshToken.ExpiresAt) {
		tokenError(w, http.StatusBadRequest, "invalid_grant",
			"refresh token has expired")
		return
	}

	if refreshToken.ClientID != client.ID {
		tokenError(w, http.StatusBadRequest, "invalid_grant",
			"refresh token was not issued to this client")
		return
	}

	// --- Step 3: スコープの検証 ---
	// リクエストされたスコープは元のスコープ以下でなければならない
	scope := r.FormValue("scope")
	if scope == "" {
		scope = refreshToken.Scope
	} else if !auth.ScopeContains(strings.Fields(refreshToken.Scope), scope) {
		tokenError(w, http.StatusBadRequest, "invalid_scope",
			"requested scope exceeds original grant scope")
		return
	}

	// --- Step 4: 旧リフレッシュトークンを無効化し、新しいものを発行（ローテーション） ---
	h.store.RevokeRefreshToken(refreshTokenStr)

	accessToken, err := h.jwtIssuer.GenerateAccessToken(refreshToken.UserID, client.ID, scope)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error",
			"failed to generate access token")
		return
	}

	newRefreshTokenStr, err := auth.GenerateRandomString(32)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error",
			"failed to generate refresh token")
		return
	}

	newRefreshToken := &model.RefreshToken{
		Token:     newRefreshTokenStr,
		ClientID:  client.ID,
		UserID:    refreshToken.UserID,
		Scope:     scope,
		ExpiresAt: time.Now().Add(model.RefreshTokenLifetime),
		Revoked:   false,
	}

	if err := h.store.SaveRefreshToken(newRefreshToken); err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error",
			"failed to save refresh token")
		return
	}

	resp := model.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(model.AccessTokenLifetime.Seconds()),
		RefreshToken: newRefreshTokenStr,
		Scope:        scope,
	}

	tokenResponse(w, resp)
}
```

## レスポンスヘルパー

```go
// tokenResponse はトークンレスポンスをJSONで返す。
func tokenResponse(w http.ResponseWriter, resp model.TokenResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")  // RFC 6749 Section 5.1
	w.Header().Set("Pragma", "no-cache")          // RFC 6749 Section 5.1
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// tokenError はエラーレスポンスをJSONで返す。
func tokenError(w http.ResponseWriter, status int, errorCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(model.ErrorResponse{
		Error:            errorCode,
		ErrorDescription: description,
	})
}

func joinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}
```

## 検証チェックリスト

認可コードグラントで必ず行う検証：

| # | 検証内容 | エラーコード |
|---|---------|------------|
| 1 | クライアント認証（ID + Secret） | `invalid_client` |
| 2 | grant_type が許可されているか | `unauthorized_client` |
| 3 | code が存在するか | `invalid_grant` |
| 4 | code が使用済みでないか | `invalid_grant` |
| 5 | code が期限切れでないか | `invalid_grant` |
| 6 | code の client_id が一致するか | `invalid_grant` |
| 7 | redirect_uri が一致するか | `invalid_grant` |
| 8 | PKCE code_verifier が正しいか | `invalid_grant` |

## レスポンスヘッダーの重要性

```
Cache-Control: no-store
Pragma: no-cache
```

RFC 6749 Section 5.1 では、トークンレスポンスにこれらのヘッダーを含めることが**必須 (MUST)** とされている。トークン情報がキャッシュされるとセキュリティリスクになるため。

## 次章

[第7章: トークン生成・検証の仕組み (JWT)](./07-token-generation.md) で、アクセストークンの実体である JWT を標準ライブラリだけで実装する。
