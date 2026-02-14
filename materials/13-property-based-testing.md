# 第13章: Property Based Testing

## Property Based Testing とは

従来のテスト（Example Based Testing）は「特定の入力 → 期待する出力」を個別に列挙する。Property Based Testing (PBT) は「どんな入力に対しても成り立つべき性質 (property)」を定義し、テストフレームワークがランダムな入力を大量に生成して性質が破られないか検証する。

```
Example Based:   f("hello") == "HELLO"
                 f("world") == "WORLD"

Property Based:  任意の文字列 s に対して len(f(s)) == len(s) が成り立つ
                 → フレームワークが "abc", "", "日本語", "a\x00b" 等を自動生成して検証
```

### なぜ認可サーバーに PBT が有効か

認可サーバーは外部からの入力を多数受け取る。攻撃者は想定外の入力を送ってくるため、手動で列挙したテストケースだけでは不十分な場合がある。PBT はエッジケースを自動的に発見してくれる。

## Go 標準ライブラリの `testing/quick`

Go には PBT のための標準パッケージ `testing/quick` がある。外部ライブラリなしで PBT を実行できる。

### 基本的な使い方

```go
import "testing/quick"

func TestProperty(t *testing.T) {
    // f が true を返す性質を、ランダム入力で100回（デフォルト）検証する
    f := func(x int) bool {
        return x + 0 == x  // 加法の単位元
    }
    if err := quick.Check(f, nil); err != nil {
        t.Error(err)
    }
}
```

`quick.Check` は：
1. 関数の引数の型に応じてランダムな値を生成する
2. デフォルトで100回繰り返す
3. 性質が破られた（`false` が返された）場合、反例を報告する

### 設定のカスタマイズ

```go
config := &quick.Config{
    MaxCount: 1000, // 試行回数を増やす
}
if err := quick.Check(f, config); err != nil {
    t.Error(err)
}
```

## 認可サーバーへの適用

### Property 1: JWT の署名・検証ラウンドトリップ

**性質**: 任意の userID, clientID, scope で生成した JWT は、同じ秘密鍵で検証すると元のクレームが復元される。

```go
// internal/token/jwt_property_test.go
package token

import (
	"testing"
	"testing/quick"
)

// Property: 生成した JWT は同じ鍵で検証すると元の情報が復元される
func TestProperty_JWTRoundTrip(t *testing.T) {
	issuer := NewJWTIssuer("property-test-secret-key-32bytes!", "http://test")

	f := func(userID, clientID, scope string) bool {
		tokenStr, err := issuer.GenerateAccessToken(userID, clientID, scope)
		if err != nil {
			return false
		}

		claims, err := issuer.VerifyAccessToken(tokenStr)
		if err != nil {
			return false
		}

		return claims.Subject == userID &&
			claims.ClientID == clientID &&
			claims.Scope == scope
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}
```

この性質が破られるケース（もし見つかったらバグ）:
- マルチバイト文字で JSON エンコード/デコードが壊れる
- Base64URL エンコードの境界条件で不正なパディングが発生する
- ヌル文字や改行が含まれる場合にパースが壊れる

### Property 2: 異なる秘密鍵では検証が必ず失敗する

**性質**: 任意の入力で生成した JWT は、異なる秘密鍵では検証に失敗する。

```go
func TestProperty_JWTDifferentKeyRejectsToken(t *testing.T) {
	issuer1 := NewJWTIssuer("key-1-property-test-secret-32b!!", "http://test")
	issuer2 := NewJWTIssuer("key-2-property-test-secret-32b!!", "http://test")

	f := func(userID, clientID, scope string) bool {
		tokenStr, err := issuer1.GenerateAccessToken(userID, clientID, scope)
		if err != nil {
			return false
		}

		_, err = issuer2.VerifyAccessToken(tokenStr)
		return err != nil // 必ずエラーになるべき
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}
```

### Property 3: PKCE のラウンドトリップ

**性質**: 任意の code_verifier から生成した code_challenge は、元の code_verifier で検証が成功する。

```go
// internal/pkce/pkce_property_test.go
package pkce

import (
	"testing"
	"testing/quick"
)

func TestProperty_PKCERoundTrip(t *testing.T) {
	f := func(codeVerifier string) bool {
		if codeVerifier == "" {
			return true // 空文字は対象外
		}
		codeChallenge := GenerateCodeChallenge(codeVerifier)
		return Verify(codeVerifier, codeChallenge, "S256")
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 1000}); err != nil {
		t.Error(err)
	}
}
```

### Property 4: PKCE は異なる verifier を拒否する

**性質**: 任意の2つの異なる code_verifier に対して、一方の verifier から生成した challenge は他方の verifier では検証に失敗する。

```go
func TestProperty_PKCEDifferentVerifierRejected(t *testing.T) {
	f := func(verifier1, verifier2 string) bool {
		if verifier1 == "" || verifier2 == "" || verifier1 == verifier2 {
			return true // 同じ値の場合はスキップ
		}
		challenge := GenerateCodeChallenge(verifier1)
		return !Verify(verifier2, challenge, "S256")
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 1000}); err != nil {
		t.Error(err)
	}
}
```

### Property 5: スコープ検証の性質

```go
// internal/auth/scope_property_test.go
package auth

import (
	"strings"
	"testing"
	"testing/quick"
)

// Property: 許可されたスコープの部分集合は常に検証に成功する
func TestProperty_ScopeSubsetAlwaysValid(t *testing.T) {
	allowed := []string{"read:profile", "write:profile", "read:posts", "write:posts"}

	f := func(indices []byte) bool {
		// ランダムなインデックスで部分集合を構築
		var subset []string
		seen := make(map[string]bool)
		for _, idx := range indices {
			i := int(idx) % len(allowed)
			s := allowed[i]
			if !seen[s] {
				subset = append(subset, s)
				seen[s] = true
			}
		}
		requested := strings.Join(subset, " ")
		return ScopeContains(allowed, requested)
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}

// Property: 許可されていないスコープを1つでも含めると検証に失敗する
func TestProperty_ScopeWithUnknownAlwaysFails(t *testing.T) {
	allowed := []string{"read:profile", "write:profile"}

	f := func(unknown string) bool {
		if unknown == "" || unknown == "read:profile" || unknown == "write:profile" {
			return true // 既知のスコープはスキップ
		}
		// 空白を含む場合はスキップ（空白はスコープ区切りとして解釈される）
		if strings.ContainsAny(unknown, " \t\n") {
			return true
		}
		return !ScopeContains(allowed, unknown)
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}
```

### Property 6: Base64URL エンコード/デコードのラウンドトリップ

```go
// internal/token/jwt_property_test.go

// Property: Base64URL エンコード→デコードで元のデータが復元される
func TestProperty_Base64URLRoundTrip(t *testing.T) {
	f := func(data []byte) bool {
		encoded := base64URLEncode(data)
		decoded, err := base64URLDecode(encoded)
		if err != nil {
			return false
		}
		if len(data) != len(decoded) {
			return false
		}
		for i := range data {
			if data[i] != decoded[i] {
				return false
			}
		}
		return true
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 1000}); err != nil {
		t.Error(err)
	}
}
```

### Property 7: ランダム文字列の一意性

```go
// internal/auth/random_property_test.go
package auth

import (
	"testing"
)

// Property: 生成されるランダム文字列は十分にユニークである
func TestProperty_RandomStringUniqueness(t *testing.T) {
	const n = 10000
	seen := make(map[string]bool, n)

	for i := 0; i < n; i++ {
		s, err := GenerateRandomString(32)
		if err != nil {
			t.Fatalf("failed to generate random string: %v", err)
		}

		if seen[s] {
			t.Fatalf("duplicate random string found after %d iterations: %s", i, s)
		}
		seen[s] = true
	}
}

// Property: 生成される文字列の長さは指定したバイト数の2倍（hex エンコード）
func TestProperty_RandomStringLength(t *testing.T) {
	lengths := []int{1, 2, 4, 8, 16, 32, 64, 128}

	for _, length := range lengths {
		s, err := GenerateRandomString(length)
		if err != nil {
			t.Fatalf("failed to generate random string: %v", err)
		}

		expectedLen := length * 2 // hex encoding doubles the length
		if len(s) != expectedLen {
			t.Errorf("GenerateRandomString(%d): got length %d, want %d",
				length, len(s), expectedLen)
		}
	}
}
```

## カスタムジェネレータ

`testing/quick` はプリミティブ型のジェネレータを内蔵しているが、ドメイン固有の値を生成したい場合は `quick.Generator` インターフェースを実装する。

```go
// OAuth2 スコープ文字列のジェネレータ
type ScopeString string

func (ScopeString) Generate(rand *rand.Rand, size int) reflect.Value {
	scopes := []string{"read:profile", "write:profile", "read:posts", "write:posts", "admin"}
	n := rand.Intn(len(scopes)) + 1

	// ランダムにn個のスコープを選択
	selected := make([]string, 0, n)
	perm := rand.Perm(len(scopes))
	for i := 0; i < n; i++ {
		selected = append(selected, scopes[perm[i]])
	}

	return reflect.ValueOf(ScopeString(strings.Join(selected, " ")))
}
```

使い方:

```go
func TestProperty_ScopeWithCustomGenerator(t *testing.T) {
	allowed := []string{"read:profile", "write:profile", "read:posts", "write:posts", "admin"}

	f := func(scope ScopeString) bool {
		// 生成されるスコープは常に allowed の部分集合なので、検証は成功するはず
		return ScopeContains(allowed, string(scope))
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
```

## PBT で見つかりやすいバグの種類

| バグの種類 | 例 |
|-----------|-----|
| 境界値 | 空文字列、非常に長い文字列、ゼロ値 |
| エンコーディング | マルチバイト文字、制御文字、ヌル文字 |
| オーバーフロー | 極端に大きな数値 |
| 不変条件の違反 | ラウンドトリップ失敗、べき等性の破れ |
| 競合状態 | 並行アクセス時の不整合（goroutine + PBT の組み合わせ） |

## Example Based Test との使い分け

| 手法 | 適するケース |
|------|------------|
| Example Based | 具体的なビジネスロジック、特定の RFC 準拠確認、既知のエッジケース |
| Property Based | エンコード/デコードのラウンドトリップ、暗号関連、入力検証の網羅性 |

両者は補完関係にある。PBT で性質を検証し、Example Based で具体的な振る舞いを保証する。

## テスト実行

```bash
# PBT を含む全テスト
go test -v ./internal/token/ ./internal/pkce/ ./internal/auth/

# 試行回数を増やして実行（-quickchecks フラグはないので Config で制御）
go test -v -count=1 ./internal/...
```

## 次章

[第14章: OpenTelemetry による可観測性](./14-opentelemetry.md) で、認可サーバーにトレーシングとメトリクスを導入する。
