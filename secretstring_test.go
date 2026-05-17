package secretstring

import "testing"

func TestString(t *testing.T) {
	secret := SecretString("my-secret-value")
	if secret.String() == "my-secret-value" {
		t.Error("String() must not return the secret value")
	}
}
