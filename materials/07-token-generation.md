# 第7章: トークン生成・検証の仕組み (JWT)

## JWT とは

JSON Web Token (JWT, RFC 7519) は、JSON ベースのクレームをコンパクトかつ安全に伝達するためのトークン形式である。

### JWT の構造

JWT は `.` で区切られた3つの部分から構成される。

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJjbGllbnRfaWQiOiJ0ZXN0LWNsaWVudCJ9.XXXX
|---- Header ----|.|--------------------- Payload --------------------|.|- Signature -|
```

1. **Header**: アルゴリズムとトークンタイプ
2. **Payload**: クレーム（トークンの中身）
3. **Signature**: 署名（改ざん検知用）

### なぜ JWT を使うか

| 方式 | 特徴 |
|------|------|
| ランダム文字列トークン | サーバー側でDB検索が必要。シンプルだがスケールしにくい |
| JWT | トークン自体に情報が含まれる。署名検証だけで有効性を確認できる |

本教材では学習のため JWT を標準ライブラリだけで自作する。

## 署名アルゴリズム: HMAC-SHA256

今回は HMAC-SHA256 (HS256) を使用する。対称鍵方式で、署名と検証に同じ秘密鍵を使う。

```
非対称鍵 (RS256等): 認可サーバーとリソースサーバーが別組織の場合に適切
対称鍵 (HS256):     認可サーバーとリソースサーバーが同じ組織の場合にシンプル
```

## Base64URL エンコーディング

JWT は Base64URL エンコーディングを使う。通常の Base64 と異なり、URL セーフな文字を使用する。

```go
// Standard Base64:    + / =
// Base64URL:          - _ (パディングなし)
```

## JWT 発行・検証の実装

```go
// internal/token/jwt.go
package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token has expired")
)

// JWTIssuer はJWTトークンの発行と検証を行う。
type JWTIssuer struct {
	secretKey []byte
	issuer    string
}

// NewJWTIssuer は新しい JWTIssuer を返す。
func NewJWTIssuer(secretKey string, issuer string) *JWTIssuer {
	return &JWTIssuer{
		secretKey: []byte(secretKey),
		issuer:    issuer,
	}
}

// Header はJWTヘッダーを表す。
type Header struct {
	Alg string `json:"alg"` // アルゴリズム
	Typ string `json:"typ"` // トークンタイプ
}

// Claims はJWTペイロード（クレーム）を表す。
// RFC 7519 Section 4.1 の登録済みクレームを使用。
type Claims struct {
	// 登録済みクレーム (Registered Claims)
	Issuer    string `json:"iss"`           // 発行者
	Subject   string `json:"sub"`           // 主体（ユーザーID）
	Audience  string `json:"aud,omitempty"` // 対象者
	ExpiresAt int64  `json:"exp"`           // 有効期限 (Unix timestamp)
	IssuedAt  int64  `json:"iat"`           // 発行時刻
	JWTID     string `json:"jti,omitempty"` // JWT固有ID

	// プライベートクレーム (Private Claims)
	ClientID string `json:"client_id"`       // OAuth2 クライアントID
	Scope    string `json:"scope,omitempty"` // スコープ
}

// GenerateAccessToken はアクセストークン（JWT）を生成する。
func (j *JWTIssuer) GenerateAccessToken(userID, clientID, scope string) (string, error) {
	now := time.Now()

	claims := Claims{
		Issuer:    j.issuer,
		Subject:   userID,
		ExpiresAt: now.Add(1 * time.Hour).Unix(),
		IssuedAt:  now.Unix(),
		ClientID:  clientID,
		Scope:     scope,
	}

	return j.sign(claims)
}

// sign はクレームを署名してJWT文字列を生成する。
func (j *JWTIssuer) sign(claims Claims) (string, error) {
	// --- Part 1: Header ---
	header := Header{
		Alg: "HS256",
		Typ: "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	headerEncoded := base64URLEncode(headerJSON)

	// --- Part 2: Payload ---
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}
	payloadEncoded := base64URLEncode(payloadJSON)

	// --- Part 3: Signature ---
	// HMAC-SHA256(secret, header.payload)
	signingInput := headerEncoded + "." + payloadEncoded
	signature := j.computeHMAC([]byte(signingInput))
	signatureEncoded := base64URLEncode(signature)

	// 最終的な JWT: header.payload.signature
	return signingInput + "." + signatureEncoded, nil
}

// VerifyAccessToken はJWTを検証しクレームを返す。
func (j *JWTIssuer) VerifyAccessToken(tokenStr string) (*Claims, error) {
	// トークンを3つの部分に分割
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	headerEncoded := parts[0]
	payloadEncoded := parts[1]
	signatureEncoded := parts[2]

	// --- Step 1: 署名の検証 ---
	signingInput := headerEncoded + "." + payloadEncoded
	expectedSignature := j.computeHMAC([]byte(signingInput))
	expectedSignatureEncoded := base64URLEncode(expectedSignature)

	// 定数時間比較でタイミング攻撃を防ぐ
	if !hmac.Equal([]byte(signatureEncoded), []byte(expectedSignatureEncoded)) {
		return nil, ErrInvalidToken
	}

	// --- Step 2: ヘッダーの検証 ---
	headerJSON, err := base64URLDecode(headerEncoded)
	if err != nil {
		return nil, ErrInvalidToken
	}

	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, ErrInvalidToken
	}

	if header.Alg != "HS256" {
		return nil, fmt.Errorf("%w: unsupported algorithm: %s", ErrInvalidToken, header.Alg)
	}

	// --- Step 3: ペイロードのデコード ---
	payloadJSON, err := base64URLDecode(payloadEncoded)
	if err != nil {
		return nil, ErrInvalidToken
	}

	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, ErrInvalidToken
	}

	// --- Step 4: 有効期限の検証 ---
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, ErrExpiredToken
	}

	// --- Step 5: 発行者の検証 ---
	if claims.Issuer != j.issuer {
		return nil, fmt.Errorf("%w: invalid issuer", ErrInvalidToken)
	}

	return &claims, nil
}

// --- ヘルパー関数 ---

// computeHMAC はHMAC-SHA256を計算する。
func (j *JWTIssuer) computeHMAC(data []byte) []byte {
	h := hmac.New(sha256.New, j.secretKey)
	h.Write(data)
	return h.Sum(nil)
}

// base64URLEncode はBase64URLエンコードする（パディングなし）。
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64URLDecode はBase64URLデコードする。
func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
```

## 署名の仕組みを詳しく見る

### HMAC-SHA256 の処理

```
入力: secretKey = "my-secret-key"
      data      = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ"

処理:
  1. SHA-256 ハッシュ関数を秘密鍵で初期化
  2. データ（header.payload）をハッシュ関数に入力
  3. 256ビット（32バイト）のMAC値を出力

出力: [32 bytes の署名データ] → Base64URLエンコード → "XXXX..."
```

### なぜ hmac.Equal を使うのか

```go
// NG: タイミング攻撃に脆弱
if signatureEncoded != expectedSignatureEncoded {
    return nil, ErrInvalidToken
}

// OK: 定数時間比較
if !hmac.Equal([]byte(signatureEncoded), []byte(expectedSignatureEncoded)) {
    return nil, ErrInvalidToken
}
```

`==` による文字列比較は、最初に不一致が見つかった時点で `false` を返す。攻撃者は比較にかかる時間を測定することで、署名の正しい部分を1文字ずつ特定できてしまう（タイミング攻撃）。

`hmac.Equal` は入力の長さに関係なく常に同じ時間で比較を完了する（定数時間比較）。

## JWT のデコード例

```go
// 使用例
issuer := token.NewJWTIssuer("super-secret-key-at-least-32-bytes!!", "http://localhost:8080")

// 発行
tokenStr, _ := issuer.GenerateAccessToken("user-1", "test-client", "read:profile")
fmt.Println(tokenStr)
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRw...

// 検証
claims, err := issuer.VerifyAccessToken(tokenStr)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("User: %s, Client: %s, Scope: %s\n", claims.Subject, claims.ClientID, claims.Scope)
```

## セキュリティに関する注意

### 秘密鍵の管理

```go
// NG: ハードコーディング
issuer := token.NewJWTIssuer("my-secret", "...")

// OK: 環境変数から取得
secretKey := os.Getenv("JWT_SECRET_KEY")
if secretKey == "" {
    log.Fatal("JWT_SECRET_KEY is not set")
}
issuer := token.NewJWTIssuer(secretKey, "...")
```

### 鍵の長さ

HS256 では最低256ビット（32バイト）の秘密鍵を使用すべき（RFC 7518 Section 3.2）。

### JWT の制限事項

- JWT は発行後に無効化できない（ステートレス）
- 短い有効期限を設定することで緩和する
- 即座の無効化が必要な場合は、ブラックリスト方式やイントロスペクションエンドポイントが必要

## 次章

[第8章: リソースサーバーとトークン検証](./08-resource-server.md) で、発行した JWT を使ってリソースを保護する方法を実装する。
