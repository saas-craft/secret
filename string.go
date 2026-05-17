package secret

import (
	"database/sql/driver"
	"encoding/json"
	"log/slog"
)

const redacted = "[REDACTED]"

type String string

func (s String) Reveal() string {
	return string(s)
}

func (s String) String() string {
	return redacted
}

func (s String) GoString() string {
	return redacted
}

func (s String) MarshalJSON() ([]byte, error) {
	return json.Marshal(redacted)
}

func (s String) MarshalText() ([]byte, error) {
	return []byte(redacted), nil
}

func (s String) MarshalBinary() ([]byte, error) {
	return []byte(redacted), nil
}

func (s String) Value() (driver.Value, error) {
	return redacted, nil
}

func (s String) LogValue() slog.Value {
	return slog.StringValue(redacted)
}
