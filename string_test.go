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
			secret := String(tc.secret)
			result := secret.Reveal()
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
			secret := String(tc.secret)
			result := fmt.Sprintf("%s", secret)
			if result != redacted {
				t.Errorf("formatted string must equal redacted value, got %q", result)
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
			secret := String(tc.secret)
			data, err := json.Marshal(secret)
			if err != nil {
				t.Fatalf("unexpected marshal error: %v", err)
			}
			if string(data) != `"`+redacted+`"` {
				t.Errorf("marshalled JSON must equal redacted value, got %s", data)
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
			secret := String(tc.secret)
			result := fmt.Sprintf("%#v", secret)
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
			secret := String(tc.secret)
			data, err := secret.MarshalText()
			if err != nil {
				t.Fatalf("unexpected marshal error: %v", err)
			}
			if string(data) != redacted {
				t.Errorf("marshalled text must equal redacted value, got %q", data)
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
			secret := String(tc.secret)
			data, err := secret.MarshalBinary()
			if err != nil {
				t.Fatalf("unexpected marshal error: %v", err)
			}
			if string(data) != redacted {
				t.Errorf("marshalled binary must equal redacted value, got %q", data)
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
			secret := String(tc.secret)
			val, err := secret.Value()
			if err != nil {
				t.Fatalf("unexpected value error: %v", err)
			}
			strVal, ok := val.(string)
			if !ok {
				t.Fatalf("expected string driver value, got %T", val)
			}
			if strVal != redacted {
				t.Errorf("driver value must equal redacted value, got %q", strVal)
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
			secret := String(tc.secret)
			val := secret.LogValue()
			if val.String() != redacted {
				t.Errorf("log value must equal redacted value, got %q", val.String())
			}
		})
	}
}

// Compile-time interface checks
var (
	_ fmt.Stringer             = String("")
	_ fmt.GoStringer           = String("")
	_ json.Marshaler           = String("")
	_ encoding.TextMarshaler   = String("")
	_ encoding.BinaryMarshaler = String("")
	_ driver.Valuer            = String("")
	_ slog.LogValuer           = String("")
)
