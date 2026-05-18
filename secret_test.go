package secret

import (
	"database/sql/driver"
	"encoding"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
)

func TestReveal(t *testing.T) {
	tests := map[string]struct {
		secret string
	}{
		"non-empty secret": {secret: "my-secret-value"},
		"one character":    {secret: "a"},
		"empty secret":     {secret: ""},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := Redact(tc.secret)
			result := s.Reveal()
			if result != tc.secret {
				t.Error("revealed secret must be the same as the original secret")
			}
		})
	}
}

func TestRevealNonString(t *testing.T) {
	tests := map[string]struct {
		secret int
	}{
		"positive": {secret: 42},
		"negative": {secret: -1},
		"zero":     {secret: 0},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := Redact(tc.secret)
			result := s.Reveal()
			if result != tc.secret {
				t.Error("revealed secret must be the same as the original secret")
			}
		})
	}
}

func TestStringer(t *testing.T) {
	tests := map[string]struct {
		secret string
	}{
		"non-empty secret": {secret: "my-secret-value"},
		"one character":    {secret: "a"},
		"empty secret":     {secret: ""},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := Redact(tc.secret)
			result := s.String()
			if result != redacted {
				t.Errorf("String() must equal redacted value, got %q", result)
			}
		})
	}
}

func TestMarshalJSON(t *testing.T) {
	tests := map[string]struct {
		secret string
	}{
		"non-empty secret": {secret: "my-secret-value"},
		"one character":    {secret: "a"},
		"empty secret":     {secret: ""},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := Redact(tc.secret)
			data, err := s.MarshalJSON()
			if err != ErrUseOfRedacted {
				t.Fatalf("expected ErrUseOfRedacted, got %v", err)
			}
			if data != nil {
				t.Errorf("marshalled JSON data must be nil, got %s", data)
			}
		})
	}
}

func TestGoStringer(t *testing.T) {
	tests := map[string]struct {
		secret string
	}{
		"non-empty secret": {secret: "my-secret-value"},
		"one character":    {secret: "a"},
		"empty secret":     {secret: ""},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := Redact(tc.secret)
			result := s.GoString()
			if result == tc.secret {
				t.Error("GoString must not expose the secret value")
			}
			if result != redacted {
				t.Errorf("GoString must equal redacted value, got %q", result)
			}
		})
	}
}

func TestMarshalText(t *testing.T) {
	tests := map[string]struct {
		secret string
	}{
		"non-empty secret": {secret: "my-secret-value"},
		"one character":    {secret: "a"},
		"empty secret":     {secret: ""},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := Redact(tc.secret)
			data, err := s.MarshalText()
			if err != ErrUseOfRedacted {
				t.Fatalf("expected ErrUseOfRedacted, got %v", err)
			}
			if data != nil {
				t.Errorf("marshalled text data must be nil, got %q", data)
			}
		})
	}
}

func TestMarshalBinary(t *testing.T) {
	tests := map[string]struct {
		secret string
	}{
		"non-empty secret": {secret: "my-secret-value"},
		"one character":    {secret: "a"},
		"empty secret":     {secret: ""},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := Redact(tc.secret)
			data, err := s.MarshalBinary()
			if err != ErrUseOfRedacted {
				t.Fatalf("expected ErrUseOfRedacted, got %v", err)
			}
			if data != nil {
				t.Errorf("marshalled binary data must be nil, got %q", data)
			}
		})
	}
}

func TestDriverValuer(t *testing.T) {
	tests := map[string]struct {
		secret string
	}{
		"non-empty secret": {secret: "my-secret-value"},
		"one character":    {secret: "a"},
		"empty secret":     {secret: ""},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := Redact(tc.secret)
			val, err := s.Value()
			if err != ErrUseOfRedacted {
				t.Fatalf("expected ErrUseOfRedacted, got %v", err)
			}
			if val != nil {
				t.Errorf("driver value must be nil, got %v", val)
			}
		})
	}
}

func TestLogValuer(t *testing.T) {
	tests := map[string]struct {
		secret string
	}{
		"non-empty secret": {secret: "my-secret-value"},
		"one character":    {secret: "a"},
		"empty secret":     {secret: ""},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := Redact(tc.secret)
			val := s.LogValue()
			if val.String() != redacted {
				t.Errorf("log value must equal redacted value, got %q", val.String())
			}
		})
	}
}

func TestFormatter(t *testing.T) {
	tests := map[string]struct {
		secret string
		verb   string
	}{
		"non-empty %v": {secret: "my-secret-value", verb: "%v"},
		"non-empty %s": {secret: "my-secret-value", verb: "%s"},
		"non-empty %q": {secret: "my-secret-value", verb: "%q"},
		"non-empty %x": {secret: "my-secret-value", verb: "%x"},
		"empty %v":     {secret: "", verb: "%v"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := Redact(tc.secret)
			result := fmt.Sprintf(tc.verb, s)
			if result != redacted {
				t.Errorf("Formatter with verb %s must equal redacted value, got %q", tc.verb, result)
			}
		})
	}
}

// Compile-time interface checks
var (
	_ fmt.Stringer             = Value[string]{}
	_ fmt.GoStringer           = Value[string]{}
	_ fmt.Formatter            = Value[string]{}
	_ json.Marshaler           = Value[string]{}
	_ encoding.TextMarshaler   = Value[string]{}
	_ encoding.BinaryMarshaler = Value[string]{}
	_ driver.Valuer            = Value[string]{}
	_ slog.LogValuer           = Value[string]{}
)
