// Package secret hides sensitive values from default formatting, logging, and serialization
package secret

import (
	"database/sql/driver"
	"encoding"
	"errors"
	"fmt"
	"log/slog"
)

const redacted = "[REDACTED]"

// Value wraps a value of type T and hides its value from default formatting, logging, and serialization.
type Value[T any] struct {
	value T
}

// ErrUseOfRedacted is returned by serialization methods; call Reveal before serializing or persisting.
var ErrUseOfRedacted = errors.New("call Reveal() to use this value")

// ErrUnsupportedType is returned by UnmarshalText when T is neither string nor encoding.TextUnmarshaler.
var ErrUnsupportedType = errors.New("type cannot unmarshal from text")

// Redact returns a Value[T] that hides v from default formatting, logging, and serialization.
func Redact[T any](v T) Value[T] {
	return Value[T]{value: v}
}

// Reveal returns the underlying value.
func (s Value[T]) Reveal() T {
	return s.value
}

// String implements fmt.Stringer and returns "[REDACTED]" for %s, %v, %q, %x, %X.
func (s Value[T]) String() string {
	return redacted
}

// GoString implements fmt.GoStringer and returns "[REDACTED]" for %#v.
func (s Value[T]) GoString() string {
	return redacted
}

// MarshalJSON implements json.Marshaler and returns ErrUseOfRedacted; call Reveal before serializing.
func (s Value[T]) MarshalJSON() ([]byte, error) {
	return nil, ErrUseOfRedacted
}

// MarshalText implements encoding.TextMarshaler and returns ErrUseOfRedacted; call Reveal before serializing.
func (s Value[T]) MarshalText() ([]byte, error) {
	return nil, ErrUseOfRedacted
}

// MarshalBinary implements encoding.BinaryMarshaler and returns ErrUseOfRedacted; call Reveal before serializing.
func (s Value[T]) MarshalBinary() ([]byte, error) {
	return nil, ErrUseOfRedacted
}

// Value implements driver.Valuer and returns ErrUseOfRedacted; call Reveal before passing to a database driver.
func (s Value[T]) Value() (driver.Value, error) {
	return nil, ErrUseOfRedacted
}

// LogValue implements slog.LogValuer and returns "[REDACTED]" for structured logging.
func (s Value[T]) LogValue() slog.Value {
	return slog.StringValue(redacted)
}

// Format implements fmt.Formatter and writes "[REDACTED]" for every verb.
func (s Value[T]) Format(f fmt.State, verb rune) {
	fmt.Fprint(f, redacted)
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Value[T]) UnmarshalText(text []byte) error {
	if u, ok := any(&s.value).(encoding.TextUnmarshaler); ok {
		return u.UnmarshalText(text)
	}

	if p, ok := any(&s.value).(*string); ok {
		*p = string(text)

		return nil
	}

	return fmt.Errorf("secret.Value[%T]: %w", s.value, ErrUnsupportedType)
}
