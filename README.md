# Secret

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
    "log/slog"

    "github.com/saas-craft/secret"
)

type Config struct {
    Host  string
    Token secret.Value[string]
}

func main() {
    cfg := Config{
        Host:  "api.saascraft.com",
        Token: secret.Redact("my-secret"),
    }

    fmt.Printf("%+v\n", cfg)
    // {Host:api.saascraft.com Token:[REDACTED]}

    fmt.Println("authenticating with:", cfg.Token.Reveal())
    // authenticating with: my-secret
}
```

## License

SaasCraft Secret is licensed under the MIT License - see [LICENSE](LICENSE) for details.
