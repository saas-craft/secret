// Package secret hides sensitive values from default formatting, logging, and serialization
package secret

import (
	"database/sql/driver"
	"encoding"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"
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

// ErrParseFailed is returned by UnmarshalText when the underlying type's UnmarshalText fails.
var ErrParseFailed = errors.New("failed to parse value")

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

// UnmarshalText implements encoding.TextUnmarshaler with a fallback for basic types.
func (s *Value[T]) UnmarshalText(text []byte) error {
	if u, ok := any(&s.value).(encoding.TextUnmarshaler); ok {
		if err := u.UnmarshalText(text); err != nil {
			return fmt.Errorf("secret.Value[%T]: %w", s.value, ErrParseFailed)
		}

		return nil
	}

	str := string(text)

	switch p := any(&s.value).(type) {
	case *string:
		*p = str

	case *bool:
		v, err := strconv.ParseBool(str)
		if err != nil {
			return fmt.Errorf("secret.Value[%T]: %w", s.value, ErrParseFailed)
		}

		*p = v

	case *int:
		v, err := strconv.ParseInt(str, 10, strconv.IntSize)
		if err != nil {
			return fmt.Errorf("secret.Value[%T]: %w", s.value, ErrParseFailed)
		}

		*p = int(v)

	case *int8:
		v, err := strconv.ParseInt(str, 10, 8)
		if err != nil {
			return fmt.Errorf("secret.Value[%T]: %w", s.value, ErrParseFailed)
		}

		*p = int8(v)

	case *int16:
		v, err := strconv.ParseInt(str, 10, 16)
		if err != nil {
			return fmt.Errorf("secret.Value[%T]: %w", s.value, ErrParseFailed)
		}

		*p = int16(v)

	case *int32:
		v, err := strconv.ParseInt(str, 10, 32)
		if err != nil {
			return fmt.Errorf("secret.Value[%T]: %w", s.value, ErrParseFailed)
		}

		*p = int32(v)

	case *int64:
		v, err := strconv.ParseInt(str, 10, 64)
		if err != nil {
			return fmt.Errorf("secret.Value[%T]: %w", s.value, ErrParseFailed)
		}

		*p = v

	case *uint:
		v, err := strconv.ParseUint(str, 10, strconv.IntSize)
		if err != nil {
			return fmt.Errorf("secret.Value[%T]: %w", s.value, ErrParseFailed)
		}

		*p = uint(v)

	case *uint8:
		v, err := strconv.ParseUint(str, 10, 8)
		if err != nil {
			return fmt.Errorf("secret.Value[%T]: %w", s.value, ErrParseFailed)
		}

		*p = uint8(v)

	case *uint16:
		v, err := strconv.ParseUint(str, 10, 16)
		if err != nil {
			return fmt.Errorf("secret.Value[%T]: %w", s.value, ErrParseFailed)
		}

		*p = uint16(v)

	case *uint32:
		v, err := strconv.ParseUint(str, 10, 32)
		if err != nil {
			return fmt.Errorf("secret.Value[%T]: %w", s.value, ErrParseFailed)
		}

		*p = uint32(v)

	case *uint64:
		v, err := strconv.ParseUint(str, 10, 64)
		if err != nil {
			return fmt.Errorf("secret.Value[%T]: %w", s.value, ErrParseFailed)
		}

		*p = v

	case *float32:
		v, err := strconv.ParseFloat(str, 32)
		if err != nil {
			return fmt.Errorf("secret.Value[%T]: %w", s.value, ErrParseFailed)
		}

		*p = float32(v)

	case *float64:
		v, err := strconv.ParseFloat(str, 64)
		if err != nil {
			return fmt.Errorf("secret.Value[%T]: %w", s.value, ErrParseFailed)
		}

		*p = v

	case *time.Duration:
		v, err := time.ParseDuration(str)
		if err != nil {
			return fmt.Errorf("secret.Value[%T]: %w", s.value, ErrParseFailed)
		}

		*p = v

	default:
		return fmt.Errorf("secret.Value[%T]: %w", s.value, ErrUnsupportedType)
	}

	return nil
}
