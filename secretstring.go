package secret

import (
	"encoding/json"
)

const redacted = "[REDACTED]"

type String string

func (s String) Reveal() string {
	return string(s)
}

func (s String) String() string {
	return redacted
}

func (s String) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}
