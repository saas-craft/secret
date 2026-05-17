# Secret

Types that hide their value when rendered to text.

```go
var refreshTokenSecret = secret.String("my-secret")

fmt.Println(refreshTokenSecret)
// Output: [REDACTED]

fmt.Println(refreshTokenSecret.Reveal())
// Output: my-secret
```

Covers the Stringer, GoStringer, TextMarshaler, json.Marshaler, BinaryMarshaler, driver.Valuer and LogValuer interfaces.

## Installation

```bash
go get github.com/saas-craft/secret
```

## Supported Types

- string

## License

SaaS Craft Secret is licensed under the MIT License - see [LICENSE](LICENSE) for details.
