// Package secret hides sensitive values from default formatting, logging, and serialization
package secret

import (
	"database/sql/driver"
	"encoding"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"reflect"
	"strconv"
	"time"
)

const redacted = "[REDACTED]"

// Value wraps a value of type T and hides its value from default formatting, logging, and serialization.
type Value[T any] struct {
	value T
}

var (
	// ErrUseOfRedacted is returned by serialization methods; call Reveal before serializing or persisting.
	ErrUseOfRedacted = errors.New("call Reveal() to use this value")

	// ErrUnsupportedType is returned by UnmarshalText when T is not a supported type.
	ErrUnsupportedType = errors.New("type cannot unmarshal from text")

	// ErrParseFailed is returned by UnmarshalText when the underlying type's parsing fails.
	ErrParseFailed = errors.New("failed to parse value")
)

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
	wrap := func(sentinel error) error {
		return fmt.Errorf("secret.Value[%T]: %w", s.value, sentinel)
	}

	if u, ok := any(&s.value).(encoding.TextUnmarshaler); ok {
		if err := u.UnmarshalText(text); err != nil {
			return wrap(ErrParseFailed)
		}
		return nil
	}

	str := string(text)

	if p, ok := any(&s.value).(*time.Duration); ok {
		v, err := time.ParseDuration(str)
		if err != nil {
			return wrap(ErrParseFailed)
		}
		*p = v
		return nil
	}

	rv := reflect.ValueOf(&s.value).Elem()
	switch rv.Kind() {
	case reflect.String:
		rv.SetString(str)

	case reflect.Bool:
		v, err := strconv.ParseBool(str)
		if err != nil {
			return wrap(ErrParseFailed)
		}
		rv.SetBool(v)

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v, err := strconv.ParseInt(str, 10, rv.Type().Bits())
		if err != nil {
			return wrap(ErrParseFailed)
		}
		rv.SetInt(v)

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v, err := strconv.ParseUint(str, 10, rv.Type().Bits())
		if err != nil {
			return wrap(ErrParseFailed)
		}
		rv.SetUint(v)

	case reflect.Float32, reflect.Float64:
		v, err := strconv.ParseFloat(str, rv.Type().Bits())
		if err != nil {
			return wrap(ErrParseFailed)
		}
		rv.SetFloat(v)

	case reflect.Struct:
		if !rv.Type().ConvertibleTo(reflect.TypeFor[url.URL]()) {
			return wrap(ErrUnsupportedType)
		}
		v, err := url.Parse(str)
		if err != nil {
			return wrap(ErrParseFailed)
		}
		rv.Set(reflect.ValueOf(*v).Convert(rv.Type()))

	default:
		return wrap(ErrUnsupportedType)
	}

	return nil
}
