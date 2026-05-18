package secret

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
)

const redacted = "[REDACTED]"

type String string

var ErrUseOfRedacted = errors.New("call Reveal() to use this value")

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
	return []byte(redacted), ErrUseOfRedacted
}

func (s String) MarshalBinary() ([]byte, error) {
	return []byte(redacted), ErrUseOfRedacted
}

func (s String) Value() (driver.Value, error) {
	return redacted, ErrUseOfRedacted
}

func (s String) LogValue() slog.Value {
	return slog.StringValue(redacted)
}

func (s String) Format(f fmt.State, verb rune) {
	fmt.Fprint(f, redacted)
}
