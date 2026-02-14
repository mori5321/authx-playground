# 第5章: 認可エンドポイントの実装

## 認可エンドポイントの役割

`/authorize` はユーザーがブラウザ経由でアクセスするエンドポイントである。以下の3段階で動作する。

1. クライアントからのリクエストを検証
2. ユーザーにログイン画面を表示し認証
3. 同意画面を表示し、認可コードを発行

## 処理フロー

```
Client                    Browser                  Authorization Server
  |                          |                            |
  |-- redirect to ---------->|                            |
  |   /authorize?...         |-- GET /authorize --------->|
  |                          |                            | リクエスト検証
  |                          |<-- ログイン画面 HTML -------|
  |                          |                            |
  |                          |-- POST /login ------------>|
  |                          |                            | ユーザー認証
  |                          |<-- 同意画面 HTML ----------|
  |                          |                            |
  |                          |-- POST /authorize -------->|
  |                          |                            | 認可コード発行
  |                          |<-- 302 redirect_uri?code= -|
  |<-- callback?code=xxx ----|                            |
```

## セッション管理

ログインと同意を2段階で行うため、簡易的なセッション管理が必要になる。標準ライブラリのみで実装する。

```go
// internal/session/session.go
package session

import (
	"authz-server/internal/auth"
	"net/http"
	"sync"
	"time"
)

// Session はユーザーセッション情報を保持する。
type Session struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time

	// 認可リクエストのパラメータを一時保存
	AuthRequest *AuthRequest
}

// AuthRequest は認可リクエストのパラメータを保持する。
// ログイン→同意の間でパラメータを引き継ぐために使う。
type AuthRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// Manager はセッションを管理する。
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewManager は新しい Manager を返す。
func NewManager() *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
	}
}

const (
	cookieName      = "authz_session"
	sessionLifetime = 30 * time.Minute
)

// Create は新しいセッションを作成し、Cookieに設定する。
func (m *Manager) Create(w http.ResponseWriter) *Session {
	id, _ := auth.GenerateRandomString(32)
	sess := &Session{
		ID:        id,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(sessionLifetime),
	}

	m.mu.Lock()
	m.sessions[id] = sess
	m.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.ExpiresAt,
	})

	return sess
}

// Get はリクエストからセッションを取得する。
func (m *Manager) Get(r *http.Request) *Session {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}

	m.mu.RLock()
	sess, ok := m.sessions[cookie.Value]
	m.mu.RUnlock()

	if !ok || time.Now().After(sess.ExpiresAt) {
		return nil
	}

	return sess
}

// Destroy はセッションを破棄する。
func (m *Manager) Destroy(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return
	}

	m.mu.Lock()
	delete(m.sessions, cookie.Value)
	m.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}
```

## HTML テンプレート

### ログイン画面

```go
// templates/login.html
```

```html
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>ログイン - Authorization Server</title>
    <style>
        body { font-family: sans-serif; max-width: 400px; margin: 80px auto; }
        form { display: flex; flex-direction: column; gap: 12px; }
        input { padding: 8px; font-size: 16px; }
        button { padding: 10px; font-size: 16px; cursor: pointer; }
        .error { color: red; }
    </style>
</head>
<body>
    <h1>ログイン</h1>
    <p><strong>{{.ClientName}}</strong> があなたのアカウントへのアクセスを要求しています。</p>
    {{if .Error}}
    <p class="error">{{.Error}}</p>
    {{end}}
    <form method="POST" action="/login">
        <input type="text" name="username" placeholder="ユーザー名" required>
        <input type="password" name="password" placeholder="パスワード" required>
        <button type="submit">ログイン</button>
    </form>
</body>
</html>
```

### 同意画面

```html
<!-- templates/consent.html -->
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>アクセス許可 - Authorization Server</title>
    <style>
        body { font-family: sans-serif; max-width: 400px; margin: 80px auto; }
        .scopes { list-style: none; padding: 0; }
        .scopes li { padding: 8px; margin: 4px 0; background: #f0f0f0; border-radius: 4px; }
        .buttons { display: flex; gap: 12px; margin-top: 20px; }
        button { padding: 10px 24px; font-size: 16px; cursor: pointer; }
        .allow { background: #4CAF50; color: white; border: none; border-radius: 4px; }
        .deny { background: #f44336; color: white; border: none; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>アクセス許可</h1>
    <p><strong>{{.ClientName}}</strong> が以下の権限を要求しています：</p>
    <ul class="scopes">
        {{range .Scopes}}
        <li>{{.}}</li>
        {{end}}
    </ul>
    <form method="POST" action="/authorize">
        <div class="buttons">
            <button type="submit" name="action" value="allow" class="allow">許可する</button>
            <button type="submit" name="action" value="deny" class="deny">拒否する</button>
        </div>
    </form>
</body>
</html>
```

## 認可ハンドラーの実装

```go
// internal/handler/authorize.go
package handler

import (
	"authz-server/internal/auth"
	"authz-server/internal/model"
	"authz-server/internal/session"
	"authz-server/internal/store"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AuthorizeHandler は認可エンドポイントを処理する。
type AuthorizeHandler struct {
	store          store.Store
	sessionManager *session.Manager
	loginTmpl      *template.Template
	consentTmpl    *template.Template
}

// NewAuthorizeHandler は新しい AuthorizeHandler を返す。
func NewAuthorizeHandler(s store.Store, sm *session.Manager) *AuthorizeHandler {
	return &AuthorizeHandler{
		store:          s,
		sessionManager: sm,
		loginTmpl:      template.Must(template.ParseFiles("templates/login.html")),
		consentTmpl:    template.Must(template.ParseFiles("templates/consent.html")),
	}
}

// HandleAuthorize は GET /authorize を処理する。
// RFC 6749 Section 4.1.1 に対応。
func (h *AuthorizeHandler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	// --- Step 1: リクエストパラメータの検証 ---

	responseType := r.URL.Query().Get("response_type")
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")

	// response_type の検証
	if responseType != model.ResponseTypeCode {
		// redirect_uri が不正な場合はリダイレクトせずエラー表示
		http.Error(w, "unsupported_response_type", http.StatusBadRequest)
		return
	}

	// client_id の検証
	client, err := h.store.GetClient(clientID)
	if err != nil {
		http.Error(w, "invalid client_id", http.StatusBadRequest)
		return
	}

	// redirect_uri の検証（完全一致）
	if !isValidRedirectURI(client, redirectURI) {
		// redirect_uri が不正な場合はリダイレクトしてはならない（RFC 6749 Section 3.1.2.4）
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	// grant_type の検証
	if !containsString(client.GrantTypes, model.GrantTypeAuthorizationCode) {
		redirectWithError(w, r, redirectURI, "unauthorized_client",
			"this client is not authorized for authorization_code grant", state)
		return
	}

	// scope の検証
	if !auth.ScopeContains(client.Scopes, scope) {
		redirectWithError(w, r, redirectURI, "invalid_scope",
			"requested scope exceeds client's allowed scopes", state)
		return
	}

	// PKCE パラメータの取得（第9章で詳細解説）
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	// --- Step 2: セッションの作成と認可リクエストの保存 ---

	sess := h.sessionManager.Create(w)
	sess.AuthRequest = &session.AuthRequest{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		ResponseType:        responseType,
		Scope:               scope,
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}

	// --- Step 3: ログイン画面の表示 ---
	h.loginTmpl.Execute(w, map[string]interface{}{
		"ClientName": client.Name,
		"Error":      "",
	})
}

// HandleLogin は POST /login を処理する。
func (h *AuthorizeHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	sess := h.sessionManager.Get(r)
	if sess == nil || sess.AuthRequest == nil {
		http.Error(w, "session not found", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// ユーザー認証
	user, err := h.store.GetUserByUsername(username)
	if err != nil || user.Password != password {
		client, _ := h.store.GetClient(sess.AuthRequest.ClientID)
		clientName := ""
		if client != nil {
			clientName = client.Name
		}
		h.loginTmpl.Execute(w, map[string]interface{}{
			"ClientName": clientName,
			"Error":      "ユーザー名またはパスワードが正しくありません",
		})
		return
	}

	// 認証成功 → セッションにユーザーIDを記録
	sess.UserID = user.ID

	// 同意画面の表示
	client, _ := h.store.GetClient(sess.AuthRequest.ClientID)
	scopes := strings.Fields(sess.AuthRequest.Scope)
	if len(scopes) == 0 {
		scopes = client.Scopes // スコープ未指定時はクライアントの全スコープ
	}

	h.consentTmpl.Execute(w, map[string]interface{}{
		"ClientName": client.Name,
		"Scopes":     scopes,
	})
}

// HandleConsent は POST /authorize (同意処理) を処理する。
func (h *AuthorizeHandler) HandleConsent(w http.ResponseWriter, r *http.Request) {
	sess := h.sessionManager.Get(r)
	if sess == nil || sess.AuthRequest == nil || sess.UserID == "" {
		http.Error(w, "session not found or not authenticated", http.StatusBadRequest)
		return
	}

	authReq := sess.AuthRequest
	action := r.FormValue("action")

	// ユーザーが拒否した場合
	if action != "allow" {
		redirectWithError(w, r, authReq.RedirectURI, "access_denied",
			"the resource owner denied the request", authReq.State)
		return
	}

	// --- 認可コードの発行 ---
	code, err := auth.GenerateRandomString(32)
	if err != nil {
		redirectWithError(w, r, authReq.RedirectURI, "server_error",
			"failed to generate authorization code", authReq.State)
		return
	}

	authCode := &model.AuthorizationCode{
		Code:                code,
		ClientID:            authReq.ClientID,
		UserID:              sess.UserID,
		RedirectURI:         authReq.RedirectURI,
		Scope:               authReq.Scope,
		ExpiresAt:           time.Now().Add(model.AuthCodeLifetime),
		Used:                false,
		CodeChallenge:       authReq.CodeChallenge,
		CodeChallengeMethod: authReq.CodeChallengeMethod,
	}

	if err := h.store.SaveAuthorizationCode(authCode); err != nil {
		redirectWithError(w, r, authReq.RedirectURI, "server_error",
			"failed to save authorization code", authReq.State)
		return
	}

	// セッションを破棄
	h.sessionManager.Destroy(w, r)

	// 認可コードをリダイレクトで返す
	redirectURL, _ := url.Parse(authReq.RedirectURI)
	q := redirectURL.Query()
	q.Set("code", code)
	if authReq.State != "" {
		q.Set("state", authReq.State)
	}
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// --- ヘルパー関数 ---

// isValidRedirectURI はリダイレクトURIが登録済みか検証する。
// RFC 6749 Section 3.1.2.3: 完全一致で比較する。
func isValidRedirectURI(client *model.Client, uri string) bool {
	for _, registeredURI := range client.RedirectURIs {
		if registeredURI == uri {
			return true
		}
	}
	return false
}

// redirectWithError はエラー情報を付加してリダイレクトする。
func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, errorCode, description, state string) {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("error", errorCode)
	q.Set("error_description", description)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func containsString(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}
```

## 重要な検証ポイントまとめ

認可エンドポイントで必ず行うべき検証を以下に整理する。

| 検証項目 | 失敗時の挙動 | RFC 参照 |
|---------|------------|---------|
| `response_type` が `code` | エラーレスポンス（リダイレクトしない） | 6749 §3.1.1 |
| `client_id` が有効 | エラーレスポンス（リダイレクトしない） | 6749 §4.1.2.1 |
| `redirect_uri` が登録済みと完全一致 | エラーレスポンス（リダイレクトしない） | 6749 §3.1.2.4 |
| `scope` がクライアントの許可範囲内 | エラーリダイレクト | 6749 §3.3 |
| クライアントが `authorization_code` を許可されている | エラーリダイレクト | 6749 §4.1.2.1 |

**`redirect_uri` が不正な場合にリダイレクトしない理由**: 攻撃者が redirect_uri を悪意のあるサイトに書き換えている可能性がある。不正な redirect_uri にリダイレクトすると、ユーザーがフィッシングサイトに誘導される。

## 次章

[第6章: トークンエンドポイントの実装](./06-token-endpoint.md) では、認可コードをアクセストークンに交換する `/token` エンドポイントを実装する。
