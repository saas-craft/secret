package secret

import (
	"encoding/json"
	"fmt"
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
