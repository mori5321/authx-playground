# 第11章: セキュリティ対策とベストプラクティス

## OAuth 2.0 の脅威モデル

RFC 6819 は OAuth 2.0 の脅威モデルを定義している。本章では主要な攻撃とその対策を解説する。

## 1. CSRF (Cross-Site Request Forgery) 攻撃

### 攻撃シナリオ

```
1. 攻撃者が自分のアカウントで認可コードを取得
2. 被害者のブラウザに
   https://client.example.com/callback?code=ATTACKER_CODE
   を踏ませる
3. 被害者のアカウントが攻撃者のリソースと紐付けられる
```

### 対策: state パラメータ

```go
// クライアント側: ランダムな state を生成してセッションに保存
state, _ := auth.GenerateRandomString(16)
// セッションに保存: session["oauth_state"] = state

// 認可リクエストに含める
// /authorize?...&state=<random_value>

// コールバックで検証
func handleCallback(w http.ResponseWriter, r *http.Request) {
    state := r.URL.Query().Get("state")
    // セッションに保存した state と比較
    // 一致しなければリクエストを拒否
    savedState := getFromSession(r, "oauth_state")
    if state != savedState {
        http.Error(w, "CSRF detected", http.StatusForbidden)
        return
    }
}
```

## 2. 認可コード横取り攻撃

### 対策: PKCE (第9章)

PKCE により、認可コードを横取りしてもトークン交換ができなくなる。

### 対策: redirect_uri の完全一致検証

```go
// NG: 部分一致やプレフィックス一致
if strings.HasPrefix(uri, registeredURI) { // 危険
    return true
}

// OK: 完全一致
if uri == registeredURI {
    return true
}
```

部分一致の場合の攻撃例:
```
登録済み: https://example.com/callback
攻撃者:   https://example.com/callback/../../../attacker.com
```

## 3. トークン漏洩

### アクセストークンの保護

```go
// 1. 短い有効期限を設定する
const AccessTokenLifetime = 1 * time.Hour // 最大でも1時間

// 2. HTTPS を強制する（本番環境）
func requireHTTPS(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Header.Get("X-Forwarded-Proto") != "https" && r.TLS == nil {
            http.Error(w, "HTTPS required", http.StatusForbidden)
            return
        }
        next.ServeHTTP(w, r)
    })
}

// 3. レスポンスにキャッシュ禁止ヘッダーを設定
w.Header().Set("Cache-Control", "no-store")
w.Header().Set("Pragma", "no-cache")
```

### リフレッシュトークンの保護

```go
// 1. トークンローテーション（第10章）
// 使用ごとに新しいトークンを発行し、古いトークンを無効化

// 2. クライアントとの紐付けを検証
if refreshToken.ClientID != client.ID {
    tokenError(w, http.StatusBadRequest, "invalid_grant",
        "refresh token was not issued to this client")
    return
}
```

## 4. クライアントなりすまし攻撃

### 対策: クライアント認証

```go
// Confidential Client: client_secret の検証が必須
// Public Client: PKCE が必須

func authenticateClient(r *http.Request, store store.Store) (*model.Client, error) {
    clientID, clientSecret, ok := parseBasicAuth(r)
    if !ok {
        clientID = r.FormValue("client_id")
        clientSecret = r.FormValue("client_secret")
    }

    client, err := store.GetClient(clientID)
    if err != nil {
        return nil, ErrInvalidClient
    }

    // Confidential Client の場合、シークレットを検証
    if client.Secret != "" {
        if clientSecret != client.Secret {
            return nil, ErrInvalidClient
        }
    }

    return client, nil
}
```

### クライアントシークレットのハッシュ化

本番環境ではクライアントシークレットをハッシュ化して保存すべきである。

```go
import (
    "crypto/sha256"
    "encoding/hex"
)

// 登録時: シークレットをハッシュ化して保存
func hashSecret(secret string) string {
    hash := sha256.Sum256([]byte(secret))
    return hex.EncodeToString(hash[:])
}

// 検証時: 入力をハッシュ化して比較
func verifySecret(input, hashedSecret string) bool {
    inputHash := hashSecret(input)
    return inputHash == hashedSecret
}
```

> 本来は bcrypt や argon2 を使うべきだが、標準ライブラリの `crypto/sha256` でも基本的なハッシュ化は可能。Go の標準ライブラリには `golang.org/x/crypto/bcrypt` があるが、これは拡張ライブラリなので本教材では SHA-256 を使う。

## 5. オープンリダイレクト攻撃

### 攻撃シナリオ

```
攻撃者が redirect_uri を悪意のあるサイトに設定:
/authorize?redirect_uri=https://evil.com/steal&...

→ 認可コードが evil.com に送信される
```

### 対策: redirect_uri の事前登録と完全一致検証

```go
func isValidRedirectURI(client *model.Client, uri string) bool {
    // 事前登録済みのURIと完全一致でなければ拒否
    for _, registeredURI := range client.RedirectURIs {
        if registeredURI == uri {
            return true
        }
    }
    return false
}
```

**redirect_uri が不正な場合はリダイレクトしてはならない。** エラーをページ上に表示する。

## 6. レート制限

ブルートフォース攻撃を防ぐための簡易的なレート制限を実装する。

```go
// internal/middleware/ratelimit.go
package middleware

import (
    "net/http"
    "sync"
    "time"
)

// RateLimiter はIPベースの簡易レート制限。
type RateLimiter struct {
    mu       sync.Mutex
    requests map[string][]time.Time
    limit    int
    window   time.Duration
}

// NewRateLimiter は新しい RateLimiter を返す。
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
    return &RateLimiter{
        requests: make(map[string][]time.Time),
        limit:    limit,
        window:   window,
    }
}

// Limit はレート制限ミドルウェアを返す。
func (rl *RateLimiter) Limit(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ip := r.RemoteAddr

        rl.mu.Lock()
        now := time.Now()

        // ウィンドウ外のリクエストを削除
        var valid []time.Time
        for _, t := range rl.requests[ip] {
            if now.Sub(t) < rl.window {
                valid = append(valid, t)
            }
        }
        rl.requests[ip] = valid

        // 制限超過チェック
        if len(rl.requests[ip]) >= rl.limit {
            rl.mu.Unlock()
            http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
            return
        }

        rl.requests[ip] = append(rl.requests[ip], now)
        rl.mu.Unlock()

        next.ServeHTTP(w, r)
    })
}
```

使い方:

```go
limiter := middleware.NewRateLimiter(10, 1*time.Minute) // 1分あたり10リクエスト

mux.Handle("POST /token", limiter.Limit(http.HandlerFunc(handleToken)))
```

## 7. ロギング

セキュリティ監査のためのログ記録。

```go
// internal/middleware/logging.go
package middleware

import (
    "log"
    "net/http"
    "time"
)

// Logging はリクエストログを記録するミドルウェア。
func Logging(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()

        // レスポンスのステータスコードを記録するためのラッパー
        wrapped := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}

        next.ServeHTTP(wrapped, r)

        log.Printf("%s %s %d %s %s",
            r.Method,
            r.URL.Path,
            wrapped.statusCode,
            time.Since(start),
            r.RemoteAddr,
        )
    })
}

type statusRecorder struct {
    http.ResponseWriter
    statusCode int
}

func (sr *statusRecorder) WriteHeader(code int) {
    sr.statusCode = code
    sr.ResponseWriter.WriteHeader(code)
}
```

**ログに含めてはいけない情報:**
- アクセストークン / リフレッシュトークンの全文
- クライアントシークレット
- パスワード

## セキュリティチェックリスト

| # | 項目 | 実装状況 |
|---|------|---------|
| 1 | redirect_uri の完全一致検証 | 第5章 |
| 2 | state パラメータによる CSRF 対策 | クライアント側で実装 |
| 3 | PKCE の実装 | 第9章 |
| 4 | 認可コードの一回限り使用 | 第6章 |
| 5 | 認可コードの短い有効期限 | 第3章（10分） |
| 6 | アクセストークンの短い有効期限 | 第3章（1時間） |
| 7 | リフレッシュトークンのローテーション | 第10章 |
| 8 | トークンレスポンスの Cache-Control: no-store | 第6章 |
| 9 | HMAC の定数時間比較 | 第7章 |
| 10 | crypto/rand によるランダム値生成 | 第4章 |
| 11 | HTTPS の強制（本番環境） | 本章 |
| 12 | レート制限 | 本章 |
| 13 | クライアントシークレットのハッシュ化 | 本章 |

## 次章

[第12章: テストの書き方と動作確認](./12-testing.md) で、実装した認可サーバーのテストを書く。
