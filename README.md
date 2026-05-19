# Secret [![CI](https://github.com/saas-craft/secret/actions/workflows/ci.yml/badge.svg)](https://github.com/saas-craft/secret/actions/workflows/ci.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/saas-craft/secret)](https://goreportcard.com/report/github.com/saas-craft/secret) [![Go Reference](https://pkg.go.dev/badge/github.com/saas-craft/secret.svg)](https://pkg.go.dev/github.com/saas-craft/secret)

A redacting wrapper that hides sensitive values from default formatting, logging, and serialization.

```go
token := secret.Redact("my-secret")

fmt.Println(token)          // [REDACTED]
fmt.Println(token.Reveal()) // my-secret
```

- **Display [REDACTED]:** Stringer, GoStringer, Formatter, LogValuer
- **Return ErrUseOfRedacted:** json.Marshaler, encoding.TextMarshaler, encoding.BinaryMarshaler, driver.Valuer

**Note:** the wrapped value can only be accessed reasonably using `Reveal()`.

## Installation

```bash
go get github.com/saas-craft/secret
```

## Usage

```go
package main

import (
    "fmt"
    "time"

    "github.com/saas-craft/secret"
)

func main() {
    type config struct {
        Host    secret.Value[string]
        Port    secret.Value[uint16]
        Timeout secret.Value[time.Duration]
    }

    cfg := config{
        Host:    secret.Redact("api.saascraft.com"),
        Port:    secret.Redact(uint16(9000)),
        Timeout: secret.Redact(5 * time.Second),
    }

    fmt.Printf("%+v\n", cfg)
    fmt.Println("Revealed:", cfg.Host.Reveal(), cfg.Port.Reveal(), cfg.Timeout.Reveal())
    // Output: {Host:[REDACTED] Port:[REDACTED] Timeout:[REDACTED]}
    // Revealed: api.saascraft.com 9000 5s
}
```

## Supported Types

| Go Type | Example value |
| --- | --- |
| `string` | `hello` |
| `bool` | `true`, `false`, `1`, `0` |
| `int`, `int8`, `int16`, `int32`, `int64` | `-42` |
| `uint`, `uint8`, `uint16`, `uint32`, `uint64` | `42` |
| `float32`, `float64` | `3.14` |
| `time.Duration` | `1h30m`, `500ms`, `2s` |
| `url.URL` | `https://saascraft.com/v1` |
| `encoding.TextUnmarshaler` (e.g. `slog.Level`) | `debug` |

## Works well with

- SaasCraft [TypedEnv](https://pkg.go.dev/github.com/saas-craft/typedenv), for type-safe environment configuration

## Constraints

- No support for named time.Duration wrapper types, which can't be distinguished from integers

## License

SaasCraft Secret is licensed under the MIT License - see [LICENSE](LICENSE) for details.
