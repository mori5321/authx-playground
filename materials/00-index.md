# Go 標準ライブラリで作る認可サーバー

OAuth 2.0 認可サーバーを Go の標準ライブラリだけで自作するための教材です。

## 対象読者

- Go の基本文法を理解している方
- HTTP の基礎知識がある方
- OAuth 2.0 を仕様レベルで理解したい方

## 教材構成

| # | ファイル | 内容 |
|---|---------|------|
| 1 | [01-oauth2-overview.md](./01-oauth2-overview.md) | OAuth 2.0 の全体像と登場人物 |
| 2 | [02-grant-types.md](./02-grant-types.md) | グラントタイプ別の認可フロー詳解 |
| 3 | [03-project-setup.md](./03-project-setup.md) | プロジェクト構成とデータモデル設計 |
| 4 | [04-client-registration.md](./04-client-registration.md) | クライアント登録とストレージ実装 |
| 5 | [05-authorization-endpoint.md](./05-authorization-endpoint.md) | 認可エンドポイントの実装 |
| 6 | [06-token-endpoint.md](./06-token-endpoint.md) | トークンエンドポイントの実装 |
| 7 | [07-token-generation.md](./07-token-generation.md) | トークン生成・検証の仕組み (JWT) |
| 8 | [08-resource-server.md](./08-resource-server.md) | リソースサーバーとトークン検証 |
| 9 | [09-pkce.md](./09-pkce.md) | PKCE (Proof Key for Code Exchange) の実装 |
| 10 | [10-refresh-token.md](./10-refresh-token.md) | リフレッシュトークンの実装 |
| 11 | [11-security.md](./11-security.md) | セキュリティ対策とベストプラクティス |
| 12 | [12-testing.md](./12-testing.md) | テストの書き方と動作確認 |

## 前提条件

- Go 1.21 以上
- 外部ライブラリは一切使用しない（標準ライブラリのみ）

## RFC 参照

本教材は以下の RFC に基づいています：

- [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) - The OAuth 2.0 Authorization Framework
- [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750) - Bearer Token Usage
- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) - JSON Web Token (JWT)
- [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) - Proof Key for Code Exchange (PKCE)
- [RFC 6819](https://datatracker.ietf.org/doc/html/rfc6819) - OAuth 2.0 Threat Model and Security Considerations
