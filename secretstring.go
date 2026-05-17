package secretstring

import (
	"encoding/json"
)

const redacted = "[REDACTED]"

type SecretString string

func (s SecretString) Reveal() string {
	return string(s)
}

func (s SecretString) String() string {
	return redacted
}

func (s SecretString) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}
