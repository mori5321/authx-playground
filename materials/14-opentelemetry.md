# 第14章: OpenTelemetry による可観測性

## なぜ認可サーバーに可観測性が必要か

認可サーバーは認証・認可の要 (chokepoint) であり、障害がシステム全体に波及する。以下の問いに答えるためにテレメトリが必要になる。

- トークン発行のレイテンシが増加していないか？
- どのクライアントが異常に多くのリクエストを送っていないか？
- 認可コードの期限切れエラーが急増していないか？
- PKCE 検証の失敗が多発していないか（攻撃の兆候）？

## OpenTelemetry (OTel) の三本柱

| シグナル | 用途 | 認可サーバーでの活用例 |
|---------|------|---------------------|
| **Traces** | リクエストの処理フローを追跡 | 認可コード発行→トークン交換の流れ |
| **Metrics** | 数値の集計・監視 | トークン発行数、エラー率、レイテンシ |
| **Logs** | イベントの記録 | 構造化ログ（本章では割愛、`log/slog` を推奨） |

## ディレクトリ構成の追加

```
authz-server/
├── internal/
│   ├── telemetry/
│   │   └── telemetry.go    # OTel 初期化
│   ├── middleware/
│   │   ├── middleware.go    # 既存
│   │   └── otel.go         # OTel ミドルウェア（新規）
│   └── ...
```

## 依存パッケージ

本章では外部ライブラリとして OpenTelemetry SDK を使用する。認可サーバーの「ビジネスロジック」は引き続き標準ライブラリのみだが、テレメトリは専用 SDK が必要である。

```bash
go get go.opentelemetry.io/otel
go get go.opentelemetry.io/otel/sdk
go get go.opentelemetry.io/otel/sdk/metric
go get go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp
go get go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp
```

## OTel SDK の初期化

```go
// internal/telemetry/telemetry.go
package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

// Init は OpenTelemetry SDK を初期化する。
// 返される cleanup 関数は main 終了時に呼び出す。
func Init(ctx context.Context, serviceName, serviceVersion string) (cleanup func(context.Context) error, err error) {
	// --- Resource: このサービスを識別する情報 ---
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(serviceVersion),
		),
	)
	if err != nil {
		return nil, err
	}

	// --- Trace Exporter ---
	traceExporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, err
	}

	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter,
			sdktrace.WithBatchTimeout(5*time.Second),
		),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)

	// --- Propagator: トレースコンテキストの伝搬方式 ---
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, // W3C Trace Context
		propagation.Baggage{},
	))

	// --- Metric Exporter ---
	metricExporter, err := otlpmetrichttp.New(ctx)
	if err != nil {
		return nil, err
	}

	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(metricExporter,
				sdkmetric.WithInterval(15*time.Second),
			),
		),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(meterProvider)

	// --- Cleanup ---
	cleanup = func(ctx context.Context) error {
		if err := tracerProvider.Shutdown(ctx); err != nil {
			return err
		}
		return meterProvider.Shutdown(ctx)
	}

	return cleanup, nil
}
```

### main.go への組み込み

```go
package main

import (
	"context"
	"authz-server/internal/telemetry"
	"log"
	"os"
	"os/signal"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// OTel 初期化
	cleanup, err := telemetry.Init(ctx, "authz-server", "1.0.0")
	if err != nil {
		log.Fatalf("failed to initialize telemetry: %v", err)
	}
	defer func() {
		if err := cleanup(ctx); err != nil {
			log.Printf("failed to shutdown telemetry: %v", err)
		}
	}()

	// ... 以降は既存のサーバー起動コード ...
}
```

## トレーシングミドルウェア

すべての HTTP リクエストに対してスパンを自動生成するミドルウェアを実装する。

```go
// internal/middleware/otel.go
package middleware

import (
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

var tracer = otel.Tracer("authz-server/middleware")

// OTelHTTP は HTTP リクエストのトレースを記録するミドルウェア。
func OTelHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 受信ヘッダーからトレースコンテキストを抽出（分散トレーシング）
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))

		// スパンの開始
		spanName := fmt.Sprintf("%s %s", r.Method, r.URL.Path)
		ctx, span := tracer.Start(ctx, spanName,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				semconv.HTTPRequestMethodKey.String(r.Method),
				semconv.URLPath(r.URL.Path),
				semconv.URLScheme(r.URL.Scheme),
				semconv.ServerAddress(r.Host),
			),
		)
		defer span.End()

		// ステータスコードを記録するためのラッパー
		wrapped := &statusRecorderOtel{ResponseWriter: w, statusCode: http.StatusOK}

		// 次のハンドラーを実行（コンテキストにスパンを渡す）
		next.ServeHTTP(wrapped, r.WithContext(ctx))

		// レスポンス情報をスパンに記録
		span.SetAttributes(
			semconv.HTTPResponseStatusCode(wrapped.statusCode),
		)

		// 4xx/5xx はエラーとしてマーク
		if wrapped.statusCode >= 400 {
			span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", wrapped.statusCode))
		}
	})
}

type statusRecorderOtel struct {
	http.ResponseWriter
	statusCode int
}

func (sr *statusRecorderOtel) WriteHeader(code int) {
	sr.statusCode = code
	sr.ResponseWriter.WriteHeader(code)
}
```

### 使い方

```go
mux := http.NewServeMux()
mux.HandleFunc("POST /token", tokenHandler.HandleToken)
// ...

// OTel ミドルウェアで全体をラップ
handler := middleware.OTelHTTP(mux)
http.ListenAndServe(":8080", handler)
```

## カスタムスパンの追加

重要な処理にはハンドラー内でカスタムスパンを追加する。

### トークンエンドポイントへのスパン追加

```go
// internal/handler/token.go （既存コードに追加）
import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

var tracer = otel.Tracer("authz-server/handler")

func (h *TokenHandler) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// --- クライアント認証のスパン ---
	ctx, authSpan := tracer.Start(ctx, "authenticate_client")
	client, err := auth.AuthenticateClient(r, h.store)
	if err != nil {
		authSpan.SetStatus(codes.Error, "client authentication failed")
		authSpan.End()
		tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	authSpan.SetAttributes(attribute.String("client_id", client.ID))
	authSpan.End()

	// --- 認可コード検証のスパン ---
	ctx, codeSpan := tracer.Start(ctx, "validate_authorization_code")
	code := r.FormValue("code")
	authCode, err := h.store.GetAuthorizationCode(code)
	if err != nil {
		codeSpan.SetStatus(codes.Error, "authorization code not found")
		codeSpan.End()
		tokenError(w, http.StatusBadRequest, "invalid_grant", "authorization code not found")
		return
	}
	codeSpan.SetAttributes(
		attribute.String("user_id", authCode.UserID),
		attribute.String("scope", authCode.Scope),
	)
	codeSpan.End()

	// --- PKCE 検証のスパン ---
	if authCode.CodeChallenge != "" {
		ctx, pkceSpan := tracer.Start(ctx, "verify_pkce")
		codeVerifier := r.FormValue("code_verifier")
		if !pkce.Verify(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			pkceSpan.SetStatus(codes.Error, "PKCE verification failed")
			pkceSpan.End()
			tokenError(w, http.StatusBadRequest, "invalid_grant", "code_verifier verification failed")
			return
		}
		pkceSpan.SetAttributes(
			attribute.String("code_challenge_method", authCode.CodeChallengeMethod),
		)
		pkceSpan.End()
	}

	// --- トークン生成のスパン ---
	_, tokenSpan := tracer.Start(ctx, "generate_tokens")
	accessToken, _ := h.jwtIssuer.GenerateAccessToken(authCode.UserID, client.ID, authCode.Scope)
	tokenSpan.End()

	// ... 以降はレスポンス返却 ...
}
```

## カスタムメトリクス

認可サーバー固有のメトリクスを定義する。

```go
// internal/telemetry/metrics.go
package telemetry

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

var meter = otel.Meter("authz-server")

// Metrics は認可サーバーのカスタムメトリクスを保持する。
type Metrics struct {
	// トークン発行数（grant_type 別）
	TokensIssued metric.Int64Counter

	// トークンエラー数（error コード別）
	TokenErrors metric.Int64Counter

	// 認可コード発行数
	AuthCodesIssued metric.Int64Counter

	// トークンエンドポイントのレイテンシ
	TokenLatency metric.Float64Histogram

	// アクティブなセッション数
	ActiveSessions metric.Int64UpDownCounter
}

// NewMetrics はメトリクス計器を初期化する。
func NewMetrics() (*Metrics, error) {
	tokensIssued, err := meter.Int64Counter("authz.tokens.issued",
		metric.WithDescription("Number of tokens issued"),
		metric.WithUnit("{token}"),
	)
	if err != nil {
		return nil, err
	}

	tokenErrors, err := meter.Int64Counter("authz.tokens.errors",
		metric.WithDescription("Number of token endpoint errors"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, err
	}

	authCodesIssued, err := meter.Int64Counter("authz.auth_codes.issued",
		metric.WithDescription("Number of authorization codes issued"),
		metric.WithUnit("{code}"),
	)
	if err != nil {
		return nil, err
	}

	tokenLatency, err := meter.Float64Histogram("authz.token.latency",
		metric.WithDescription("Token endpoint latency"),
		metric.WithUnit("ms"),
		metric.WithExplicitBucketBoundaries(1, 5, 10, 25, 50, 100, 250, 500, 1000),
	)
	if err != nil {
		return nil, err
	}

	activeSessions, err := meter.Int64UpDownCounter("authz.sessions.active",
		metric.WithDescription("Number of active sessions"),
		metric.WithUnit("{session}"),
	)
	if err != nil {
		return nil, err
	}

	return &Metrics{
		TokensIssued:   tokensIssued,
		TokenErrors:    tokenErrors,
		AuthCodesIssued: authCodesIssued,
		TokenLatency:   tokenLatency,
		ActiveSessions: activeSessions,
	}, nil
}
```

### メトリクスの記録

```go
// internal/handler/token.go （既存コードに追加）
import (
	"go.opentelemetry.io/otel/attribute"
)

func (h *TokenHandler) HandleToken(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	// ... 既存の処理 ...

	// 処理完了後にメトリクスを記録
	elapsed := float64(time.Since(start).Milliseconds())
	h.metrics.TokenLatency.Record(ctx, elapsed,
		metric.WithAttributes(
			attribute.String("grant_type", grantType),
		),
	)
}

// トークン発行成功時
func (h *TokenHandler) recordTokenIssued(ctx context.Context, grantType, clientID string) {
	h.metrics.TokensIssued.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("grant_type", grantType),
			attribute.String("client_id", clientID),
		),
	)
}

// エラー時
func (h *TokenHandler) recordTokenError(ctx context.Context, errorCode, grantType string) {
	h.metrics.TokenErrors.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("error", errorCode),
			attribute.String("grant_type", grantType),
		),
	)
}
```

## ローカルでの動作確認 (Jaeger + Prometheus)

### docker-compose.yml

```yaml
# docker-compose.yml
services:
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"   # Jaeger UI
      - "4318:4318"     # OTLP HTTP receiver
    environment:
      - COLLECTOR_OTLP_ENABLED=true

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
```

### 環境変数

```bash
# OTLP エクスポーターの接続先
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf

# サーバーの起動
go run main.go
```

### 確認方法

1. **Jaeger UI** (`http://localhost:16686`): トレースの可視化

   - Service: `authz-server` を選択
   - Operation: `POST /token` 等のスパンが表示される
   - 各スパンのアトリビュート（`client_id`, `grant_type` 等）を確認

2. **Prometheus** (`http://localhost:9090`): メトリクスのクエリ

   ```promql
   # grant_type 別のトークン発行数
   sum by (grant_type) (authz_tokens_issued_total)

   # エラー率
   sum(rate(authz_tokens_errors_total[5m])) / sum(rate(authz_tokens_issued_total[5m]))

   # p99 レイテンシ
   histogram_quantile(0.99, rate(authz_token_latency_bucket[5m]))
   ```

## トレースの可視化例

Jaeger で表示されるトレースのイメージ:

```
POST /token [200 OK] ─── 45ms ────────────────────────────────────┐
  ├── authenticate_client ─── 2ms ───┐                            │
  │   client_id: test-client         │                            │
  │                                  │                            │
  ├── validate_authorization_code ── 1ms ─┐                       │
  │   user_id: user-1                     │                       │
  │   scope: read:profile                 │                       │
  │                                       │                       │
  ├── verify_pkce ─── 1ms ─┐              │                       │
  │   method: S256          │              │                       │
  │                         │              │                       │
  └── generate_tokens ─── 3ms ─┐          │                       │
                                │          │                       │
                                └──────────┴───────────────────────┘
```

## 分散トレーシング: 認可サーバー → リソースサーバー

クライアントがアクセストークンを取得してリソースにアクセスする場合、トレースコンテキストを HTTP ヘッダー (`traceparent`) で伝搬させることで、認可サーバーとリソースサーバーのスパンを1つのトレースとして結合できる。

```
クライアント
  ├── POST /token (認可サーバー)
  │     trace_id: abc123
  │
  └── GET /api/profile (リソースサーバー)
        trace_id: abc123  ← 同じトレースID
        parent_span_id: xxx
```

リソースサーバー側にも同じ `OTelHTTP` ミドルウェアを適用すれば、`traceparent` ヘッダーからコンテキストが自動的に復元される。

## 本番運用で監視すべきメトリクス

| メトリクス | アラート条件の例 |
|-----------|----------------|
| `authz.tokens.errors` (error=invalid_client) | 5分間で100件以上 → ブルートフォースの可能性 |
| `authz.tokens.errors` (error=invalid_grant) | 急増 → 認可コード漏洩の可能性 |
| `authz.token.latency` p99 | 500ms 超過 → パフォーマンス問題 |
| `authz.tokens.issued` (grant_type=client_credentials) | 特定 client_id からの急増 → 異常なアクセスパターン |

## まとめ

本教材では、OAuth 2.0 認可サーバーを Go の標準ライブラリで実装し、以下のコンポーネントを作成した：

1. **データモデル** — Client, AuthorizationCode, Token 等の構造体
2. **インメモリストア** — スレッドセーフなデータストア
3. **認可エンドポイント** — ログイン画面、同意画面、認可コード発行
4. **トークンエンドポイント** — 3種類のグラントタイプに対応
5. **JWT** — HMAC-SHA256 による署名・検証
6. **リソースサーバー** — Bearer トークン検証ミドルウェア
7. **PKCE** — 認可コード横取り攻撃の対策
8. **リフレッシュトークン** — トークンローテーション
9. **セキュリティ対策** — CSRF, レート制限, ロギング
10. **テスト** — ユニットテスト、runn による API 統合テスト
11. **Property Based Testing** — `testing/quick` による網羅的テスト
12. **OpenTelemetry** — トレーシングとメトリクスによる可観測性

### 参考 RFC 一覧

| RFC | タイトル |
|-----|---------|
| RFC 6749 | The OAuth 2.0 Authorization Framework |
| RFC 6750 | Bearer Token Usage |
| RFC 6819 | OAuth 2.0 Threat Model and Security Considerations |
| RFC 7519 | JSON Web Token (JWT) |
| RFC 7636 | Proof Key for Code Exchange (PKCE) |
| RFC 7009 | OAuth 2.0 Token Revocation |
| RFC 7662 | OAuth 2.0 Token Introspection |
