# 第8章: リソースサーバーとトークン検証

## リソースサーバーの役割

リソースサーバーは保護されたリソース（API）を提供する。クライアントから送られてくるアクセストークン (JWT) を検証し、正当なリクエストにのみリソースを返す。

```
Client                      Resource Server
  |                              |
  |-- GET /api/profile --------->|
  |   Authorization: Bearer xxx  |
  |                              | 1. トークンを抽出
  |                              | 2. JWT を検証
  |                              | 3. スコープを確認
  |                              | 4. リソースを返す
  |<-- 200 OK + JSON ------------|
```

## Bearer トークンの送信方法 (RFC 6750)

クライアントがアクセストークンを送信する方法は RFC 6750 で定義されている。

### Authorization ヘッダー（推奨）

```
GET /api/profile HTTP/1.1
Host: resource.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

これが最も推奨される方法。

## トークン検証ミドルウェア

リソースサーバー側でトークンを検証するミドルウェアを実装する。

```go
// internal/middleware/middleware.go
package middleware

import (
	"authz-server/internal/token"
	"context"
	"net/http"
	"strings"
)

// contextKey はコンテキストキーの型。
type contextKey string

const (
	ClaimsKey contextKey = "claims"
)

// RequireAuth はBearer トークンを検証するミドルウェア。
// RFC 6750 Section 2.1 に対応。
func RequireAuth(jwtIssuer *token.JWTIssuer, requiredScope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// --- Step 1: Authorization ヘッダーからトークンを抽出 ---
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				unauthorizedError(w, "missing authorization header")
				return
			}

			// "Bearer " プレフィックスの確認
			const prefix = "Bearer "
			if !strings.HasPrefix(authHeader, prefix) {
				unauthorizedError(w, "authorization header must use Bearer scheme")
				return
			}

			tokenStr := authHeader[len(prefix):]
			if tokenStr == "" {
				unauthorizedError(w, "bearer token is empty")
				return
			}

			// --- Step 2: JWT の検証 ---
			claims, err := jwtIssuer.VerifyAccessToken(tokenStr)
			if err != nil {
				switch err {
				case token.ErrExpiredToken:
					unauthorizedError(w, "token has expired")
				default:
					unauthorizedError(w, "invalid token")
				}
				return
			}

			// --- Step 3: スコープの検証 ---
			if requiredScope != "" {
				if !hasScope(claims.Scope, requiredScope) {
					forbiddenError(w, "insufficient scope")
					return
				}
			}

			// --- Step 4: クレームをコンテキストに格納 ---
			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClaims はコンテキストからクレームを取得する。
func GetClaims(r *http.Request) *token.Claims {
	claims, ok := r.Context().Value(ClaimsKey).(*token.Claims)
	if !ok {
		return nil
	}
	return claims
}

// hasScope はトークンのスコープに要求されたスコープが含まれるか検証する。
func hasScope(tokenScope, requiredScope string) bool {
	scopes := strings.Fields(tokenScope)
	for _, s := range scopes {
		if s == requiredScope {
			return true
		}
	}
	return false
}

// unauthorizedError は 401 Unauthorized を返す。
// RFC 6750 Section 3 に対応。
func unauthorizedError(w http.ResponseWriter, description string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+description+`"`)
	http.Error(w, description, http.StatusUnauthorized)
}

// forbiddenError は 403 Forbidden を返す。
// RFC 6750 Section 3.1 に対応。
func forbiddenError(w http.ResponseWriter, description string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", error_description="`+description+`"`)
	http.Error(w, description, http.StatusForbidden)
}
```

## リソースサーバーの実装

```go
// resource-server/main.go
package main

import (
	"authz-server/internal/middleware"
	"authz-server/internal/token"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

// Profile はユーザープロフィールを表す。
type Profile struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

func main() {
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		secretKey = "super-secret-key-at-least-32-bytes!!" // 開発用
	}

	jwtIssuer := token.NewJWTIssuer(secretKey, "http://localhost:8080")

	mux := http.NewServeMux()

	// 保護されたエンドポイント
	mux.Handle("GET /api/profile",
		middleware.RequireAuth(jwtIssuer, "read:profile")(
			http.HandlerFunc(handleProfile),
		),
	)

	// 公開エンドポイント（トークン不要）
	mux.HandleFunc("GET /api/public", handlePublic)

	addr := ":8081"
	fmt.Printf("Resource Server listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		http.Error(w, "claims not found", http.StatusInternalServerError)
		return
	}

	// 実際にはDBからユーザー情報を取得する
	profile := Profile{
		ID:       claims.Subject,
		Username: "testuser",
		Email:    "testuser@example.com",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profile)
}

func handlePublic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "this is a public endpoint",
	})
}
```

## ミドルウェアの使い方パターン

### エンドポイントごとに異なるスコープを要求

```go
// read:profile スコープが必要
mux.Handle("GET /api/profile",
    middleware.RequireAuth(jwtIssuer, "read:profile")(
        http.HandlerFunc(handleGetProfile),
    ),
)

// write:profile スコープが必要
mux.Handle("PUT /api/profile",
    middleware.RequireAuth(jwtIssuer, "write:profile")(
        http.HandlerFunc(handleUpdateProfile),
    ),
)

// スコープ不問（トークンの存在だけ確認）
mux.Handle("GET /api/me",
    middleware.RequireAuth(jwtIssuer, "")(
        http.HandlerFunc(handleMe),
    ),
)
```

## WWW-Authenticate ヘッダー

RFC 6750 Section 3 では、トークンエラー時に `WWW-Authenticate` ヘッダーを返すことが規定されている。

```
// トークンなし
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer

// トークンが無効
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token", error_description="token has expired"

// スコープ不足
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope", error_description="insufficient scope"
```

## 動作確認

```bash
# 1. 認可サーバーを起動
go run main.go

# 2. リソースサーバーを起動（別ターミナル）
go run resource-server/main.go

# 3. 公開エンドポイント（トークン不要）
curl http://localhost:8081/api/public
# {"message":"this is a public endpoint"}

# 4. 保護されたエンドポイント（トークンなし → 401）
curl -i http://localhost:8081/api/profile
# HTTP/1.1 401 Unauthorized
# WWW-Authenticate: Bearer error="invalid_token", error_description="missing authorization header"

# 5. 保護されたエンドポイント（有効なトークン → 200）
# まず認可フローを通じてアクセストークンを取得し...
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..." http://localhost:8081/api/profile
# {"id":"user-1","username":"testuser","email":"testuser@example.com"}
```

## 次章

[第9章: PKCE (Proof Key for Code Exchange) の実装](./09-pkce.md) で、認可コードの横取り攻撃を防ぐ PKCE を実装する。
