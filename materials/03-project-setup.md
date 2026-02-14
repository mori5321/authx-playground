# 第3章: プロジェクト構成とデータモデル設計

## ディレクトリ構成

```
authz-server/
├── main.go                 # エントリーポイント
├── go.mod
├── internal/
│   ├── auth/
│   │   └── auth.go         # ユーザー認証ロジック
│   ├── handler/
│   │   ├── authorize.go    # /authorize エンドポイント
│   │   ├── token.go        # /token エンドポイント
│   │   ├── consent.go      # 同意画面
│   │   └── login.go        # ログイン画面
│   ├── middleware/
│   │   └── middleware.go   # ロギング等のミドルウェア
│   ├── model/
│   │   └── model.go        # データモデル定義
│   ├── store/
│   │   └── memory.go       # インメモリストア
│   ├── token/
│   │   └── jwt.go          # JWT トークン生成・検証
│   └── pkce/
│       └── pkce.go         # PKCE 検証
├── resource-server/
│   └── main.go             # リソースサーバー（テスト用）
└── templates/
    ├── login.html           # ログイン画面テンプレート
    └── consent.html         # 同意画面テンプレート
```

## プロジェクトの初期化

```bash
mkdir authz-server && cd authz-server
go mod init authz-server
```

## データモデルの定義

`internal/model/model.go` に核となるデータ構造を定義する。

```go
package model

import (
	"time"
)

// Client はOAuth 2.0クライアントを表す。
// RFC 6749 Section 2 に対応。
type Client struct {
	ID           string
	Secret       string // ハッシュ化して保存すべき
	RedirectURIs []string
	GrantTypes   []string // "authorization_code", "client_credentials", "refresh_token"
	Scopes       []string // このクライアントが要求可能なスコープ
	Name         string   // 同意画面に表示する名前
}

// AuthorizationCode は認可コードを表す。
// RFC 6749 Section 4.1.2 に対応。
type AuthorizationCode struct {
	Code        string
	ClientID    string
	UserID      string
	RedirectURI string
	Scope       string
	ExpiresAt   time.Time
	Used        bool // 一度使用されたら再利用不可

	// PKCE (RFC 7636)
	CodeChallenge       string
	CodeChallengeMethod string
}

// AccessToken はアクセストークンのメタデータを表す。
// 実際のトークン文字列はJWTとして生成する。
type AccessToken struct {
	Token     string
	ClientID  string
	UserID    string
	Scope     string
	ExpiresAt time.Time
}

// RefreshToken はリフレッシュトークンを表す。
type RefreshToken struct {
	Token     string
	ClientID  string
	UserID    string
	Scope     string
	ExpiresAt time.Time
	Revoked   bool
}

// User はリソースオーナー（ユーザー）を表す。
// 認可サーバーがユーザーを認証するために必要。
type User struct {
	ID       string
	Username string
	Password string // 本番ではbcryptなどでハッシュ化すべき
}

// TokenResponse はトークンエンドポイントのレスポンスを表す。
// RFC 6749 Section 5.1 に対応。
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// ErrorResponse はOAuth 2.0エラーレスポンスを表す。
// RFC 6749 Section 5.2 に対応。
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}
```

### 各フィールドの解説

#### Client

```go
type Client struct {
	ID           string     // 公開識別子。クライアント登録時に生成する
	Secret       string     // 秘密鍵。Confidential Client のみ
	RedirectURIs []string   // 登録済みリダイレクトURI。セキュリティ上必須
	GrantTypes   []string   // 許可するグラントタイプ
	Scopes       []string   // 要求可能なスコープの上限
	Name         string     // 人間が読める名前
}
```

**なぜ RedirectURIs を事前登録するのか？**

認可コードをリダイレクトで渡す際、攻撃者が redirect_uri を書き換えると認可コードを盗めてしまう。事前に登録されたURIとの完全一致を検証することで、これを防ぐ。

#### AuthorizationCode

```go
type AuthorizationCode struct {
	Code        string     // ランダムに生成された文字列
	ClientID    string     // どのクライアントに発行されたか
	UserID      string     // どのユーザーが認可したか
	RedirectURI string     // トークン交換時にも一致を検証
	Scope       string     // 認可されたスコープ
	ExpiresAt   time.Time  // 有効期限（短く設定する）
	Used        bool       // 再利用防止フラグ
}
```

**なぜ Used フラグが必要か？**

RFC 6749 Section 4.1.2: 認可コードは一度しか使用できない。もし認可コードが複数回使用された場合、その認可コードに紐づくすべてのトークンを無効化すべき (SHOULD)。これは漏洩の検知メカニズムである。

## 定数の定義

```go
package model

// トークンの有効期間
const (
	AuthCodeLifetime       = 10 * time.Minute
	AccessTokenLifetime    = 1 * time.Hour
	RefreshTokenLifetime   = 24 * time.Hour * 30 // 30日
)

// グラントタイプ
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeRefreshToken      = "refresh_token"
)

// レスポンスタイプ
const (
	ResponseTypeCode = "code"
)
```

## サーバーのエントリーポイント

`main.go` の骨格を作る。

```go
package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()

	// エンドポイントの登録（後の章で実装する）
	mux.HandleFunc("GET /authorize", handleAuthorize)
	mux.HandleFunc("POST /authorize", handleAuthorizePost)
	mux.HandleFunc("POST /token", handleToken)

	addr := ":8080"
	fmt.Printf("Authorization Server listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// プレースホルダー（後の章で実装）
func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("authorize endpoint"))
}

func handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("authorize post endpoint"))
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("token endpoint"))
}
```

> **Note**: Go 1.22 以降では `http.NewServeMux()` でメソッドベースのルーティング（`"GET /authorize"` のような書き方）がサポートされている。

## 動作確認

```bash
go run main.go
# 別ターミナルで
curl http://localhost:8080/authorize
# => authorize endpoint
```

## 次章

[第4章: クライアント登録とストレージ実装](./04-client-registration.md) で、インメモリストアとクライアント管理を実装する。
