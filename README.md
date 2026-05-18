# Secret

Types that defensively hide their value when rendered to text.

```go
var refreshTokenSecret = secret.String("my-secret")

fmt.Println(refreshTokenSecret)
// Output: [REDACTED]

fmt.Println(refreshTokenSecret.Reveal())
// Output: my-secret
```

Covers the Stringer, GoStringer, Formatter, TextMarshaler, json.Marshaler, BinaryMarshaler, driver.Valuer and LogValuer interfaces. Returns an ErrUseOfRedacted error when possible.

**Note**: easily circumvented with a cast eg. string(refreshTokenSecret).

## Installation

```bash
go get github.com/saas-craft/secret
```

## Supported Types

- string

## License

SaasCraft Secret is licensed under the MIT License - see [LICENSE](LICENSE) for details.
