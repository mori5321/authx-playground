# 第2章: グラントタイプ別の認可フロー詳解

## グラントタイプ一覧

RFC 6749 では4つのグラントタイプが定義されている。

| グラントタイプ | 用途 | 今回実装するか |
|--------------|------|-------------|
| Authorization Code | Web アプリ、モバイルアプリ | Yes (メイン) |
| Implicit | SPA (非推奨) | No |
| Resource Owner Password Credentials | 信頼できるアプリ (非推奨) | No |
| Client Credentials | サーバー間通信 | Yes |

現代の OAuth 2.0 では **Authorization Code Grant + PKCE** が推奨される。Implicit Grant は Security BCP で非推奨となっている。

## 1. Authorization Code Grant（認可コードグラント）

最も一般的かつ安全なフロー。

### フロー図

```
+----------+                                +---------------+
|          |---(1) Authorization Request--->|               |
|          |     (response_type=code)       | Authorization |
|  User    |                                |    Server     |
|  Agent   |<--(2) Login & Consent Screen---|               |
| (Browser)|                                |               |
|          |---(3) User Authenticates ----->|               |
|          |       & Grants Consent         |               |
|          |                                |               |
|          |<--(4) Redirect with Auth Code--|               |
+----------+       (code=xxx)              +---------------+
     |                                           ^
     | (4) code を Client に渡す                   |
     v                                           |
+----------+                                     |
|          |---(5) Token Request --------------->|
|  Client  |     (grant_type=authorization_code)
|  (App)   |     (code=xxx)
|          |                                +---------------+
|          |<--(6) Access Token ------------|               |
|          |       Refresh Token            | Authorization |
+----------+                                |    Server     |
                                            +---------------+
```

### ステップ詳細

#### (1) 認可リクエスト

クライアントがブラウザを認可エンドポイントにリダイレクトする。

```
GET /authorize?
  response_type=code
  &client_id=s6BhdRkqt3
  &redirect_uri=https://client.example.org/callback
  &scope=read:profile
  &state=xyz123
```

| パラメータ | 必須 | 説明 |
|-----------|------|------|
| response_type | Yes | `code` を指定 |
| client_id | Yes | 登録済みクライアントの ID |
| redirect_uri | 条件付き | 認可後のリダイレクト先 |
| scope | No | 要求するスコープ |
| state | 推奨 | CSRF 対策用のランダム文字列 |

#### (2)(3) ユーザー認証と同意

認可サーバーが：
1. ユーザーにログイン画面を表示
2. ユーザーを認証
3. 同意画面を表示（「このアプリに以下の権限を許可しますか？」）
4. ユーザーが許可/拒否を選択

#### (4) 認可コードの発行

同意後、認可サーバーはブラウザを redirect_uri にリダイレクトする。

```
HTTP/1.1 302 Found
Location: https://client.example.org/callback?
  code=SplxlOBeZQQYbYS6WxSbIA
  &state=xyz123
```

認可コードの特性：
- 一度だけ使用可能
- 有効期間が短い（推奨: 10分以内）
- client_id と紐付けられている

#### (5) トークンリクエスト

クライアントが認可コードをトークンエンドポイントに送信する。

```
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https://client.example.org/callback
```

#### (6) トークンレスポンス

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
  "scope": "read:profile"
}
```

## 2. Client Credentials Grant（クライアントクレデンシャルグラント）

サーバー間通信（Machine-to-Machine）で使用する。ユーザーが介在しない。

### フロー図

```
+----------+                                +---------------+
|          |---(1) Token Request ---------->|               |
|  Client  |     grant_type=client_credentials Authorization |
|  (M2M)   |     Authorization: Basic ...   |    Server     |
|          |                                |               |
|          |<--(2) Access Token ------------|               |
+----------+                                +---------------+
```

### リクエスト

```
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=client_credentials
&scope=read:stats
```

### レスポンス

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read:stats"
}
```

注意: Client Credentials Grant ではリフレッシュトークンを発行すべきではない（RFC 6749 Section 4.4.3）。

## エラーレスポンス

### 認可エンドポイントのエラー

redirect_uri にエラー情報を付加してリダイレクトする。

```
HTTP/1.1 302 Found
Location: https://client.example.org/callback?
  error=access_denied
  &error_description=The+resource+owner+denied+the+request
  &state=xyz123
```

| error コード | 意味 |
|-------------|------|
| invalid_request | パラメータ不足・不正 |
| unauthorized_client | クライアントが許可されていない |
| access_denied | ユーザーが拒否した |
| unsupported_response_type | サポートしていない response_type |
| invalid_scope | 無効なスコープ |
| server_error | サーバー内部エラー |

### トークンエンドポイントのエラー

JSON でエラーを返す。

```json
{
  "error": "invalid_grant",
  "error_description": "The authorization code has expired"
}
```

| error コード | 意味 |
|-------------|------|
| invalid_request | パラメータ不足・不正 |
| invalid_client | クライアント認証に失敗 |
| invalid_grant | 認可コード/リフレッシュトークンが無効 |
| unauthorized_client | このグラントタイプが許可されていない |
| unsupported_grant_type | サポートしていない grant_type |
| invalid_scope | 無効なスコープ |

## 実装の優先度

本教材では以下の順で実装する：

1. **Authorization Code Grant** - 最も基本的で重要なフロー
2. **PKCE 拡張** - セキュリティ強化のため必須
3. **Refresh Token** - トークンの更新
4. **Client Credentials Grant** - M2M 通信用

## 次章

[第3章: プロジェクト構成とデータモデル設計](./03-project-setup.md) では、実際のコードを書き始める準備をする。
