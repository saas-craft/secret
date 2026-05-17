package secretstring

import "strings"

type SecretString string

func (s SecretString) Reveal() string {
	return string(s)
}

func (s SecretString) String() string {
	return strings.Repeat("*", max(len(s), 1))
}
