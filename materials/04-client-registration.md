# 第4章: クライアント登録とストレージ実装

## インメモリストアの設計

本教材ではデータベースを使わず、インメモリストアで実装する。本番環境では PostgreSQL 等に置き換えること。

スレッドセーフにするため `sync.RWMutex` を使用する。

## ストアのインターフェース

まず、ストレージ層のインターフェースを定義する。

```go
// internal/store/store.go
package store

import (
	"authz-server/internal/model"
	"errors"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
)

// Store は認可サーバーのデータストアインターフェース。
type Store interface {
	// Client
	GetClient(id string) (*model.Client, error)
	SaveClient(client *model.Client) error

	// User
	GetUser(id string) (*model.User, error)
	GetUserByUsername(username string) (*model.User, error)
	SaveUser(user *model.User) error

	// Authorization Code
	SaveAuthorizationCode(code *model.AuthorizationCode) error
	GetAuthorizationCode(code string) (*model.AuthorizationCode, error)
	DeleteAuthorizationCode(code string) error

	// Refresh Token
	SaveRefreshToken(token *model.RefreshToken) error
	GetRefreshToken(token string) (*model.RefreshToken, error)
	RevokeRefreshToken(token string) error
}
```

## インメモリストアの実装

```go
// internal/store/memory.go
package store

import (
	"authz-server/internal/model"
	"sync"
)

// MemoryStore はインメモリのデータストア。
type MemoryStore struct {
	mu sync.RWMutex

	clients            map[string]*model.Client            // key: client_id
	users              map[string]*model.User              // key: user_id
	authorizationCodes map[string]*model.AuthorizationCode // key: code
	refreshTokens      map[string]*model.RefreshToken      // key: token
}

// NewMemoryStore は新しい MemoryStore を返す。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		clients:            make(map[string]*model.Client),
		users:              make(map[string]*model.User),
		authorizationCodes: make(map[string]*model.AuthorizationCode),
		refreshTokens:      make(map[string]*model.RefreshToken),
	}
}

// --- Client ---

func (s *MemoryStore) GetClient(id string) (*model.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, ok := s.clients[id]
	if !ok {
		return nil, ErrNotFound
	}
	return client, nil
}

func (s *MemoryStore) SaveClient(client *model.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.clients[client.ID] = client
	return nil
}

// --- User ---

func (s *MemoryStore) GetUser(id string) (*model.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.users[id]
	if !ok {
		return nil, ErrNotFound
	}
	return user, nil
}

func (s *MemoryStore) GetUserByUsername(username string) (*model.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.users {
		if user.Username == username {
			return user, nil
		}
	}
	return nil, ErrNotFound
}

func (s *MemoryStore) SaveUser(user *model.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.users[user.ID] = user
	return nil
}

// --- Authorization Code ---

func (s *MemoryStore) SaveAuthorizationCode(code *model.AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.authorizationCodes[code.Code] = code
	return nil
}

func (s *MemoryStore) GetAuthorizationCode(code string) (*model.AuthorizationCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ac, ok := s.authorizationCodes[code]
	if !ok {
		return nil, ErrNotFound
	}
	return ac, nil
}

func (s *MemoryStore) DeleteAuthorizationCode(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.authorizationCodes, code)
	return nil
}

// --- Refresh Token ---

func (s *MemoryStore) SaveRefreshToken(token *model.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.refreshTokens[token.Token] = token
	return nil
}

func (s *MemoryStore) GetRefreshToken(token string) (*model.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rt, ok := s.refreshTokens[token]
	if !ok {
		return nil, ErrNotFound
	}
	return rt, nil
}

func (s *MemoryStore) RevokeRefreshToken(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rt, ok := s.refreshTokens[token]
	if !ok {
		return ErrNotFound
	}
	rt.Revoked = true
	return nil
}
```

### 設計上のポイント

1. **`sync.RWMutex`**: 読み取りは並行実行可能、書き込みは排他的
2. **インターフェース分離**: `Store` インターフェースにより、後からDB実装に差し替えられる
3. **ポインタで返す**: 構造体のコピーコストを避ける（ただし外部からの変更に注意）

## テスト用データの登録

サーバー起動時にテスト用のクライアントとユーザーを登録する。

```go
// internal/store/seed.go
package store

import "authz-server/internal/model"

// Seed はテスト用の初期データを登録する。
func Seed(s Store) {
	// テスト用クライアント
	s.SaveClient(&model.Client{
		ID:           "test-client",
		Secret:       "test-secret", // 本番ではハッシュ化
		RedirectURIs: []string{"http://localhost:3000/callback"},
		GrantTypes: []string{
			model.GrantTypeAuthorizationCode,
			model.GrantTypeRefreshToken,
		},
		Scopes: []string{"read:profile", "write:profile", "read:posts"},
		Name:   "Test Application",
	})

	// M2M クライアント
	s.SaveClient(&model.Client{
		ID:         "m2m-client",
		Secret:     "m2m-secret",
		GrantTypes: []string{model.GrantTypeClientCredentials},
		Scopes:     []string{"read:stats"},
		Name:       "Backend Service",
	})

	// テスト用ユーザー
	s.SaveUser(&model.User{
		ID:       "user-1",
		Username: "testuser",
		Password: "password", // 本番ではbcryptハッシュ
	})
}
```

## クライアント認証ユーティリティ

トークンエンドポイントでクライアントを認証するためのユーティリティを作る。

```go
// internal/auth/client.go
package auth

import (
	"authz-server/internal/model"
	"authz-server/internal/store"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

var (
	ErrInvalidClient = errors.New("invalid client credentials")
)

// AuthenticateClient はHTTPリクエストからクライアントを認証する。
// RFC 6749 Section 2.3 に対応。
// Basic認証またはPOSTボディのclient_id/client_secretを使う。
func AuthenticateClient(r *http.Request, s store.Store) (*model.Client, error) {
	clientID, clientSecret, ok := parseBasicAuth(r)
	if !ok {
		// Basic認証がない場合、POSTボディから取得を試みる
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	if clientID == "" {
		return nil, ErrInvalidClient
	}

	client, err := s.GetClient(clientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	// Confidential Client はシークレットの検証が必要
	if client.Secret != "" {
		if clientSecret != client.Secret {
			return nil, ErrInvalidClient
		}
	}

	return client, nil
}

// parseBasicAuth は Authorization ヘッダーから Basic 認証情報を取得する。
// Go 標準の r.BasicAuth() を使わず自前実装する理由は学習目的のため。
func parseBasicAuth(r *http.Request) (username, password string, ok bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", "", false
	}

	// "Basic <base64>" の形式をパースする
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}

	// "username:password" を分離
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	return parts[0], parts[1], true
}
```

### Basic 認証のエンコード例

```
client_id:client_secret
→ Base64 エンコード
→ Authorization: Basic dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ=
```

```bash
echo -n "test-client:test-secret" | base64
# dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ=
```

## ランダム文字列の生成ユーティリティ

認可コードやトークンの生成に使うランダム文字列生成関数。

```go
// internal/auth/random.go
package auth

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateRandomString は暗号学的に安全なランダム文字列を生成する。
// 認可コード、リフレッシュトークンなどに使用する。
func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
```

**なぜ `crypto/rand` を使うのか？**

`math/rand` は予測可能な擬似乱数を生成する。認可コードやトークンが予測されると攻撃者に盗まれるため、暗号学的に安全な `crypto/rand` を使う必要がある。

## スコープの検証ユーティリティ

```go
// internal/auth/scope.go
package auth

import "strings"

// ScopeContains は許可されたスコープに要求されたスコープが含まれるか検証する。
func ScopeContains(allowed []string, requested string) bool {
	if requested == "" {
		return true
	}

	requestedScopes := strings.Fields(requested)
	allowedSet := make(map[string]bool)
	for _, s := range allowed {
		allowedSet[s] = true
	}

	for _, s := range requestedScopes {
		if !allowedSet[s] {
			return false
		}
	}
	return true
}
```

## 次章

[第5章: 認可エンドポイントの実装](./05-authorization-endpoint.md) では、`/authorize` エンドポイントを実装し、ログイン画面と同意画面を作成する。
