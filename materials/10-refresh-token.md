# 第10章: リフレッシュトークンの実装

## なぜリフレッシュトークンが必要か

アクセストークンは短い有効期限（例: 1時間）に設定すべきである。しかし、有効期限が切れるたびにユーザーに再ログインを求めるのは UX が悪い。

リフレッシュトークンは、ユーザーの操作なしに新しいアクセストークンを取得するための仕組みである。

```
アクセストークンの寿命:     |========| (1時間)
リフレッシュトークンの寿命: |================================================| (30日)

アクセストークン期限切れ時:
  Client --> /token (refresh_token=xxx) --> 新しいアクセストークン
```

## アクセストークン vs リフレッシュトークン

| 項目 | アクセストークン | リフレッシュトークン |
|------|----------------|-------------------|
| 送信先 | リソースサーバー | 認可サーバーのみ |
| 有効期間 | 短い（分〜時間） | 長い（日〜月） |
| 形式 | JWT（自己完結型） | ランダム文字列（参照型） |
| 検証方法 | 署名検証（ステートレス） | DB 参照（ステートフル） |
| 漏洩時のリスク | 限定的（短寿命） | 高い（長寿命） |

## リフレッシュトークンのライフサイクル

```
1. 初回トークン発行
   Authorization Code → Access Token + Refresh Token (RT1)

2. アクセストークン期限切れ
   RT1 → 新 Access Token + 新 Refresh Token (RT2)
   RT1 は無効化される

3. 再度期限切れ
   RT2 → 新 Access Token + 新 Refresh Token (RT3)
   RT2 は無効化される

4. RT1 が使用された場合（漏洩の兆候）
   RT1 は既に無効化されているので拒否
   → すべての関連トークンを無効化すべき
```

## トークンローテーション

リフレッシュトークンを使用するたびに新しいリフレッシュトークンを発行し、古いものを無効化する方式を**トークンローテーション**と呼ぶ。

### ローテーションのメリット

1. **漏洩検知**: 古いリフレッシュトークンが使用された場合、漏洩を検知できる
2. **被害限定**: 攻撃者がリフレッシュトークンを盗んでも、正規ユーザーが先に使えば無効化される

### 実装（第6章で実装済みの部分を再掲）

```go
func (h *TokenHandler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	// ... クライアント認証、トークン検証 ...

	// ★ ローテーション: 旧トークンを無効化
	h.store.RevokeRefreshToken(refreshTokenStr)

	// 新しいアクセストークンを発行
	accessToken, _ := h.jwtIssuer.GenerateAccessToken(
		refreshToken.UserID, client.ID, scope)

	// ★ 新しいリフレッシュトークンを発行
	newRefreshTokenStr, _ := auth.GenerateRandomString(32)
	newRefreshToken := &model.RefreshToken{
		Token:     newRefreshTokenStr,
		ClientID:  client.ID,
		UserID:    refreshToken.UserID,
		Scope:     scope,
		ExpiresAt: time.Now().Add(model.RefreshTokenLifetime),
		Revoked:   false,
	}
	h.store.SaveRefreshToken(newRefreshToken)

	// レスポンスに新しいリフレッシュトークンを含める
	resp := model.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(model.AccessTokenLifetime.Seconds()),
		RefreshToken: newRefreshTokenStr, // ★ 新しいリフレッシュトークン
		Scope:        scope,
	}
	tokenResponse(w, resp)
}
```

## スコープの縮小

リフレッシュ時に元のスコープより狭いスコープを要求できる。広いスコープは要求できない。

```bash
# 元のスコープ: "read:profile write:profile"

# OK: スコープを縮小
curl -X POST http://localhost:8080/token \
  -u "test-client:test-secret" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=xxx" \
  -d "scope=read:profile"

# NG: スコープの拡大は拒否される
curl -X POST http://localhost:8080/token \
  -u "test-client:test-secret" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=xxx" \
  -d "scope=read:profile write:profile delete:profile"
# → {"error":"invalid_scope","error_description":"requested scope exceeds original grant scope"}
```

## リフレッシュトークンの保存場所（クライアント側）

| 保存場所 | セキュリティ | 用途 |
|---------|------------|------|
| サーバーサイドセッション | 高 | Web アプリ（BFF パターン） |
| HttpOnly Cookie | 中 | Web アプリ |
| Secure Storage | 中 | モバイルアプリ（Keychain, Keystore） |
| localStorage | 低（非推奨） | SPA（XSS に脆弱） |

## 動作確認

```bash
# 1. まず認可コードフローでトークンを取得
# （アクセストークンとリフレッシュトークンが返る）

# 2. リフレッシュトークンで新しいトークンを取得
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "test-client:test-secret" \
  -d "grant_type=refresh_token&refresh_token=<REFRESH_TOKEN>"

# レスポンス:
# {
#   "access_token": "eyJ...(新しい)",
#   "token_type": "Bearer",
#   "expires_in": 3600,
#   "refresh_token": "abc...(新しい)",
#   "scope": "read:profile"
# }

# 3. 古いリフレッシュトークンを再利用 → エラー
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "test-client:test-secret" \
  -d "grant_type=refresh_token&refresh_token=<OLD_REFRESH_TOKEN>"

# → {"error":"invalid_grant","error_description":"refresh token has been revoked"}
```

## 次章

[第11章: セキュリティ対策とベストプラクティス](./11-security.md) で、認可サーバー全体のセキュリティ強化策を解説する。
