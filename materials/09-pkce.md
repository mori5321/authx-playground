# 第9章: PKCE (Proof Key for Code Exchange) の実装

## PKCE とは

PKCE (RFC 7636, "ピクシー" と発音) は、認可コードの横取り攻撃を防ぐ拡張仕様である。

元々はモバイルアプリやネイティブアプリ向けに設計されたが、現在は **すべてのクライアントタイプで推奨** されている（OAuth 2.0 Security BCP）。

## 攻撃シナリオ: なぜ PKCE が必要か

### PKCE なしの場合

```
                          攻撃者のアプリ
                              |
                              | 認可コードを横取り
                              v
User --> Browser --> AuthServer --> redirect_uri?code=xxx
                                        |
                                        | 正規のアプリに届くはずだった
                                        v
                                   正規の Client
```

モバイルアプリでは、カスタムURLスキーム（`myapp://callback`）を使ってリダイレクトを受ける。しかし、悪意のあるアプリが同じカスタムURLスキームを登録すると、認可コードを横取りできてしまう。

### PKCE ありの場合

攻撃者は認可コードを横取りできても、`code_verifier` を知らないのでトークン交換ができない。

## PKCE の仕組み

### 全体フロー

```
Client                          Authorization Server
  |                                     |
  | 1. code_verifier を生成             |
  |    (ランダムな文字列)               |
  |                                     |
  | 2. code_challenge を計算            |
  |    SHA256(code_verifier)            |
  |    → Base64URL エンコード           |
  |                                     |
  | 3. /authorize に送信 ------------->  |
  |    code_challenge=xxx               | code_challenge を
  |    code_challenge_method=S256       | 認可コードと紐付けて保存
  |                                     |
  | <-- code=yyy -----------------------|
  |                                     |
  | 4. /token に送信 ----------------->  |
  |    code=yyy                         | code_verifier から
  |    code_verifier=zzz               | SHA256 を計算し
  |                                     | 保存済みの code_challenge
  |                                     | と比較
  |                                     |
  | <-- access_token -------------------|
```

### パラメータ

| パラメータ | 送信先 | 説明 |
|-----------|-------|------|
| `code_verifier` | `/token` | 43〜128文字のランダム文字列 |
| `code_challenge` | `/authorize` | `code_verifier` のSHA256ハッシュ (Base64URL) |
| `code_challenge_method` | `/authorize` | `S256` (推奨) または `plain` |

### チャレンジの計算

```
code_challenge = BASE64URL(SHA256(code_verifier))
```

`plain` メソッドの場合:
```
code_challenge = code_verifier
```

`plain` は推奨されない。`S256` を使うべき。

## 実装

```go
// internal/pkce/pkce.go
package pkce

import (
	"crypto/sha256"
	"encoding/base64"
)

// Verify は code_verifier と保存済みの code_challenge を検証する。
// RFC 7636 Section 4.6 に対応。
func Verify(codeVerifier, codeChallenge, method string) bool {
	if codeVerifier == "" || codeChallenge == "" {
		return false
	}

	switch method {
	case "S256", "": // デフォルトは S256
		return verifyS256(codeVerifier, codeChallenge)
	case "plain":
		return codeVerifier == codeChallenge
	default:
		return false
	}
}

// verifyS256 は S256 メソッドで検証する。
// BASE64URL(SHA256(code_verifier)) == code_challenge
func verifyS256(codeVerifier, codeChallenge string) bool {
	// SHA256 ハッシュを計算
	hash := sha256.Sum256([]byte(codeVerifier))

	// Base64URL エンコード（パディングなし）
	computed := base64.RawURLEncoding.EncodeToString(hash[:])

	return computed == codeChallenge
}

// GenerateCodeChallenge は code_verifier から code_challenge を生成する。
// クライアント側で使用するユーティリティ。
func GenerateCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
```

## クライアント側の実装例

PKCE はクライアント側で `code_verifier` の生成と `code_challenge` の計算を行う。

```go
// client/pkce_example.go
package main

import (
	"authz-server/internal/auth"
	"authz-server/internal/pkce"
	"fmt"
	"net/url"
)

func startAuthorizationFlow() {
	// Step 1: code_verifier を生成
	// RFC 7636 Section 4.1: 43〜128文字の unreserved characters
	codeVerifier, _ := auth.GenerateRandomString(32) // 64文字のhex文字列

	// Step 2: code_challenge を計算
	codeChallenge := pkce.GenerateCodeChallenge(codeVerifier)

	// Step 3: 認可リクエストを構築
	authURL := url.URL{
		Scheme: "http",
		Host:   "localhost:8080",
		Path:   "/authorize",
	}
	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", "test-client")
	q.Set("redirect_uri", "http://localhost:3000/callback")
	q.Set("scope", "read:profile")
	q.Set("state", "random-state-value")
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	authURL.RawQuery = q.Encode()

	fmt.Printf("Open this URL in browser:\n%s\n", authURL.String())
	fmt.Printf("\nSave this code_verifier for token exchange:\n%s\n", codeVerifier)

	// Step 4: ユーザーが認可し、callback?code=xxx を受け取った後...
	// exchangeToken(code, codeVerifier)
}

func exchangeToken(code, codeVerifier string) {
	// POST /token に code_verifier を含めて送信
	// form values:
	//   grant_type=authorization_code
	//   code=<received_code>
	//   redirect_uri=http://localhost:3000/callback
	//   client_id=test-client
	//   client_secret=test-secret
	//   code_verifier=<saved_code_verifier>
	fmt.Printf("Exchange code=%s with code_verifier=%s\n", code, codeVerifier)
}
```

## 認可サーバーへの組み込み

PKCE は第5章と第6章で既に組み込み済みだが、フローを整理する。

### 認可エンドポイント側（第5章の HandleAuthorize）

```go
// code_challenge と code_challenge_method を受け取り、
// 認可コードに紐付けて保存する
codeChallenge := r.URL.Query().Get("code_challenge")
codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

authCode := &model.AuthorizationCode{
    // ...
    CodeChallenge:       codeChallenge,
    CodeChallengeMethod: codeChallengeMethod,
}
```

### トークンエンドポイント側（第6章の handleAuthorizationCodeGrant）

```go
// 認可コードに code_challenge が紐付いている場合、
// code_verifier の検証を行う
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
```

## PKCE を必須にすべきか

OAuth 2.0 Security BCP では、**すべての認可コードグラントで PKCE を必須にすることを推奨**している。

```go
// PKCE を必須にする場合の追加検証（認可エンドポイント側）
if codeChallenge == "" {
    redirectWithError(w, r, redirectURI, "invalid_request",
        "code_challenge is required", state)
    return
}
```

## 動作確認

```bash
# 1. code_verifier を生成
CODE_VERIFIER=$(openssl rand -hex 32)
echo "code_verifier: $CODE_VERIFIER"

# 2. code_challenge を計算
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
echo "code_challenge: $CODE_CHALLENGE"

# 3. 認可リクエスト（ブラウザで開く）
echo "http://localhost:8080/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:3000/callback&scope=read:profile&state=test&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256"

# 4. 認可後、受け取った code でトークン交換
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "test-client:test-secret" \
  -d "grant_type=authorization_code" \
  -d "code=<RECEIVED_CODE>" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "code_verifier=$CODE_VERIFIER"
```

## 次章

[第10章: リフレッシュトークンの実装](./10-refresh-token.md) で、トークンの更新メカニズムを詳しく見ていく。
