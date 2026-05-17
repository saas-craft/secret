package secretstring

import (
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
			secret := SecretString(tc.secret)
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
			secret := SecretString(tc.secret)
			result := fmt.Sprintf("%s", secret)
			if result == tc.secret {
				t.Error("formatted string must not be the secret value")
			}
		})
	}
}
