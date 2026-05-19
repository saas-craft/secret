package secret

import (
	"database/sql/driver"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func Example() {
	type config struct {
		Host    Value[string]
		Port    Value[uint16]
		Timeout Value[time.Duration]
	}

	cfg := config{
		Host:    Redact("api.saascraft.com"),
		Port:    Redact(uint16(9000)),
		Timeout: Redact(5 * time.Second),
	}

	fmt.Printf("%+v\n", cfg)
	fmt.Println("Revealed:", cfg.Host.Reveal(), cfg.Port.Reveal(), cfg.Timeout.Reveal())
	// Output: {Host:[REDACTED] Port:[REDACTED] Timeout:[REDACTED]}
	// Revealed: api.saascraft.com 9000 5s
}

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
			if !errors.Is(err, ErrUseOfRedacted) {
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
			if !errors.Is(err, ErrUseOfRedacted) {
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
			if !errors.Is(err, ErrUseOfRedacted) {
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
			if !errors.Is(err, ErrUseOfRedacted) {
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
			if val.Kind() != slog.KindString {
				t.Errorf("log value must be KindString, got %v", val.Kind())
			}
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

type stubTextUnmarshaler struct {
	val   string
	count int8
}

func (u *stubTextUnmarshaler) UnmarshalText(text []byte) error {
	u.val = string(text)
	u.count = int8(len(text))
	return nil
}

var errTextUnmarshal = errors.New("text unmarshal failed")

type failingTextUnmarshaler struct {
	val string
}

func (u *failingTextUnmarshaler) UnmarshalText([]byte) error {
	return errTextUnmarshal
}

func TestUnmarshalText(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		tests := map[string]struct {
			input []byte
			want  string
		}{
			"non-empty": {input: []byte("my-secret"), want: "my-secret"},
			"empty":     {input: []byte{}, want: ""},
			"nil":       {input: nil, want: ""},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				var s Value[string]
				if err := s.UnmarshalText(tc.input); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got := s.Reveal(); got != tc.want {
					t.Errorf("Reveal() = %q, want %q", got, tc.want)
				}
			})
		}
	})

	t.Run("TextUnmarshaler success delegates to underlying type", func(t *testing.T) {
		var s Value[stubTextUnmarshaler]
		if err := s.UnmarshalText([]byte("delegated")); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got := s.Reveal()
		if got.val != "delegated" {
			t.Errorf("Reveal().val = %q, want %q", got.val, "delegated")
		}
		if got.count != int8(len("delegated")) {
			t.Errorf("Reveal().count = %d, want %d", got.count, int8(len("delegated")))
		}
	})

	t.Run("TextUnmarshaler populates int8 field correctly", func(t *testing.T) {
		tests := map[string]struct {
			input     []byte
			wantVal   string
			wantCount int8
		}{
			"non-empty": {input: []byte("hello"), wantVal: "hello", wantCount: 5},
			"empty":     {input: []byte{}, wantVal: "", wantCount: 0},
			"nil":       {input: nil, wantVal: "", wantCount: 0},
			"max int8":  {input: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), wantVal: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", wantCount: 127},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				var s Value[stubTextUnmarshaler]
				if err := s.UnmarshalText(tc.input); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				got := s.Reveal()
				if got.val != tc.wantVal {
					t.Errorf("Reveal().val = %q, want %q", got.val, tc.wantVal)
				}
				if got.count != tc.wantCount {
					t.Errorf("Reveal().count = %d, want %d", got.count, tc.wantCount)
				}
			})
		}
	})

	t.Run("TextUnmarshaler error is wrapped as ErrParseFailed", func(t *testing.T) {
		var s Value[failingTextUnmarshaler]
		err := s.UnmarshalText([]byte("anything"))
		if !errors.Is(err, ErrParseFailed) {
			t.Fatalf("expected ErrParseFailed, got %v", err)
		}
		if errors.Is(err, errTextUnmarshal) {
			t.Fatal("underlying error must not be exposed (would leak sensitive data)")
		}
	})

	t.Run("TextUnmarshaler value is not mutated on error", func(t *testing.T) {
		s := Redact(failingTextUnmarshaler{val: "original"})
		if err := s.UnmarshalText([]byte("anything")); !errors.Is(err, ErrParseFailed) {
			t.Fatalf("expected ErrParseFailed, got %v", err)
		}
		if got := s.Reveal().val; got != "original" {
			t.Errorf("value mutated on error path: got %q, want %q", got, "original")
		}
	})

	t.Run("unsupported type returns ErrUnsupportedType", func(t *testing.T) {
		type opaque struct{ val string }
		var s Value[opaque]
		if err := s.UnmarshalText([]byte("anything")); !errors.Is(err, ErrUnsupportedType) {
			t.Fatalf("want ErrUnsupportedType, got %v", err)
		}
	})

	t.Run("bool", func(t *testing.T) {
		tests := map[string]struct {
			input   []byte
			want    bool
			wantErr bool
		}{
			"true":          {input: []byte("true"), want: true},
			"false":         {input: []byte("false"), want: false},
			"1":             {input: []byte("1"), want: true},
			"0":             {input: []byte("0"), want: false},
			"t":             {input: []byte("t"), want: true},
			"f":             {input: []byte("f"), want: false},
			"T":             {input: []byte("T"), want: true},
			"F":             {input: []byte("F"), want: false},
			"TRUE":          {input: []byte("TRUE"), want: true},
			"FALSE":         {input: []byte("FALSE"), want: false},
			"invalid yes":   {input: []byte("yes"), wantErr: true},
			"invalid no":    {input: []byte("no"), wantErr: true},
			"invalid empty": {input: []byte(""), wantErr: true},
			"invalid 2":     {input: []byte("2"), wantErr: true},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				var s Value[bool]
				err := s.UnmarshalText(tc.input)
				if tc.wantErr {
					if !errors.Is(err, ErrParseFailed) {
						t.Fatalf("want ErrParseFailed, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got := s.Reveal(); got != tc.want {
					t.Errorf("Reveal() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("bool value not mutated on error", func(t *testing.T) {
		s := Redact(true)
		if err := s.UnmarshalText([]byte("yes")); !errors.Is(err, ErrParseFailed) {
			t.Fatalf("expected ErrParseFailed, got %v", err)
		}
		if got := s.Reveal(); !got {
			t.Error("value mutated on error: got false, want true")
		}
	})

	t.Run("int", func(t *testing.T) {
		tests := map[string]struct {
			input   []byte
			want    int
			wantErr bool
		}{
			"zero":         {input: []byte("0"), want: 0},
			"positive":     {input: []byte("42"), want: 42},
			"negative":     {input: []byte("-42"), want: -42},
			"max":          {input: []byte(strconv.Itoa(math.MaxInt)), want: math.MaxInt},
			"min":          {input: []byte(strconv.Itoa(math.MinInt)), want: math.MinInt},
			"overflow max": {input: []byte(strconv.FormatUint(uint64(math.MaxInt)+1, 10)), wantErr: true},
			"overflow min": {input: []byte("-" + strconv.FormatUint(uint64(math.MaxInt)+2, 10)), wantErr: true},
			"non-numeric":  {input: []byte("abc"), wantErr: true},
			"float":        {input: []byte("1.5"), wantErr: true},
			"empty":        {input: []byte(""), wantErr: true},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				var s Value[int]
				err := s.UnmarshalText(tc.input)
				if tc.wantErr {
					if !errors.Is(err, ErrParseFailed) {
						t.Fatalf("want ErrParseFailed, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got := s.Reveal(); got != tc.want {
					t.Errorf("Reveal() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("int8", func(t *testing.T) {
		tests := map[string]struct {
			input   []byte
			want    int8
			wantErr bool
		}{
			"zero":         {input: []byte("0"), want: 0},
			"positive":     {input: []byte("1"), want: 1},
			"negative":     {input: []byte("-1"), want: -1},
			"max":          {input: []byte("127"), want: math.MaxInt8},
			"min":          {input: []byte("-128"), want: math.MinInt8},
			"overflow max": {input: []byte("128"), wantErr: true},
			"overflow min": {input: []byte("-129"), wantErr: true},
			"non-numeric":  {input: []byte("abc"), wantErr: true},
			"empty":        {input: []byte(""), wantErr: true},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				var s Value[int8]
				err := s.UnmarshalText(tc.input)
				if tc.wantErr {
					if !errors.Is(err, ErrParseFailed) {
						t.Fatalf("want ErrParseFailed, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got := s.Reveal(); got != tc.want {
					t.Errorf("Reveal() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("int8 value not mutated on error", func(t *testing.T) {
		s := Redact(int8(99))
		if err := s.UnmarshalText([]byte("abc")); !errors.Is(err, ErrParseFailed) {
			t.Fatalf("expected ErrParseFailed, got %v", err)
		}
		if got := s.Reveal(); got != 99 {
			t.Errorf("value mutated on error: got %v, want 99", got)
		}
	})

	t.Run("int16", func(t *testing.T) {
		tests := map[string]struct {
			input   []byte
			want    int16
			wantErr bool
		}{
			"zero":         {input: []byte("0"), want: 0},
			"positive":     {input: []byte("1"), want: 1},
			"negative":     {input: []byte("-1"), want: -1},
			"max":          {input: []byte("32767"), want: math.MaxInt16},
			"min":          {input: []byte("-32768"), want: math.MinInt16},
			"overflow max": {input: []byte("32768"), wantErr: true},
			"overflow min": {input: []byte("-32769"), wantErr: true},
			"non-numeric":  {input: []byte("abc"), wantErr: true},
			"empty":        {input: []byte(""), wantErr: true},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				var s Value[int16]
				err := s.UnmarshalText(tc.input)
				if tc.wantErr {
					if !errors.Is(err, ErrParseFailed) {
						t.Fatalf("want ErrParseFailed, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got := s.Reveal(); got != tc.want {
					t.Errorf("Reveal() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("int32", func(t *testing.T) {
		tests := map[string]struct {
			input   []byte
			want    int32
			wantErr bool
		}{
			"zero":         {input: []byte("0"), want: 0},
			"positive":     {input: []byte("1"), want: 1},
			"negative":     {input: []byte("-1"), want: -1},
			"max":          {input: []byte("2147483647"), want: math.MaxInt32},
			"min":          {input: []byte("-2147483648"), want: math.MinInt32},
			"overflow max": {input: []byte("2147483648"), wantErr: true},
			"overflow min": {input: []byte("-2147483649"), wantErr: true},
			"non-numeric":  {input: []byte("abc"), wantErr: true},
			"empty":        {input: []byte(""), wantErr: true},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				var s Value[int32]
				err := s.UnmarshalText(tc.input)
				if tc.wantErr {
					if !errors.Is(err, ErrParseFailed) {
						t.Fatalf("want ErrParseFailed, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got := s.Reveal(); got != tc.want {
					t.Errorf("Reveal() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("int64", func(t *testing.T) {
		tests := map[string]struct {
			input   []byte
			want    int64
			wantErr bool
		}{
			"zero":         {input: []byte("0"), want: 0},
			"positive":     {input: []byte("42"), want: 42},
			"negative":     {input: []byte("-42"), want: -42},
			"max":          {input: []byte("9223372036854775807"), want: math.MaxInt64},
			"min":          {input: []byte("-9223372036854775808"), want: math.MinInt64},
			"overflow max": {input: []byte("9223372036854775808"), wantErr: true},
			"overflow min": {input: []byte("-9223372036854775809"), wantErr: true},
			"non-numeric":  {input: []byte("abc"), wantErr: true},
			"float":        {input: []byte("1.5"), wantErr: true},
			"empty":        {input: []byte(""), wantErr: true},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				var s Value[int64]
				err := s.UnmarshalText(tc.input)
				if tc.wantErr {
					if !errors.Is(err, ErrParseFailed) {
						t.Fatalf("want ErrParseFailed, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got := s.Reveal(); got != tc.want {
					t.Errorf("Reveal() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("uint", func(t *testing.T) {
		tests := map[string]struct {
			input   []byte
			want    uint
			wantErr bool
		}{
			"zero":        {input: []byte("0"), want: 0},
			"positive":    {input: []byte("42"), want: 42},
			"max":         {input: []byte(strconv.FormatUint(uint64(math.MaxUint), 10)), want: math.MaxUint},
			"negative":    {input: []byte("-1"), wantErr: true},
			"overflow":    {input: []byte(strconv.FormatUint(math.MaxUint64, 10) + "0"), wantErr: true},
			"non-numeric": {input: []byte("abc"), wantErr: true},
			"float":       {input: []byte("1.5"), wantErr: true},
			"empty":       {input: []byte(""), wantErr: true},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				var s Value[uint]
				err := s.UnmarshalText(tc.input)
				if tc.wantErr {
					if !errors.Is(err, ErrParseFailed) {
						t.Fatalf("want ErrParseFailed, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got := s.Reveal(); got != tc.want {
					t.Errorf("Reveal() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("uint8", func(t *testing.T) {
		tests := map[string]struct {
			input   []byte
			want    uint8
			wantErr bool
		}{
			"zero":        {input: []byte("0"), want: 0},
			"positive":    {input: []byte("1"), want: 1},
			"max":         {input: []byte("255"), want: math.MaxUint8},
			"mid":         {input: []byte("128"), want: 128},
			"overflow":    {input: []byte("256"), wantErr: true},
			"negative":    {input: []byte("-1"), wantErr: true},
			"non-numeric": {input: []byte("abc"), wantErr: true},
			"empty":       {input: []byte(""), wantErr: true},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				var s Value[uint8]
				err := s.UnmarshalText(tc.input)
				if tc.wantErr {
					if !errors.Is(err, ErrParseFailed) {
						t.Fatalf("want ErrParseFailed, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got := s.Reveal(); got != tc.want {
					t.Errorf("Reveal() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("uint16", func(t *testing.T) {
		tests := map[string]struct {
			input   []byte
			want    uint16
			wantErr bool
		}{
			"zero":        {input: []byte("0"), want: 0},
			"positive":    {input: []byte("1"), want: 1},
			"max":         {input: []byte("65535"), want: math.MaxUint16},
			"overflow":    {input: []byte("65536"), wantErr: true},
			"negative":    {input: []byte("-1"), wantErr: true},
			"non-numeric": {input: []byte("abc"), wantErr: true},
			"empty":       {input: []byte(""), wantErr: true},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				var s Value[uint16]
				err := s.UnmarshalText(tc.input)
				if tc.wantErr {
					if !errors.Is(err, ErrParseFailed) {
						t.Fatalf("want ErrParseFailed, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got := s.Reveal(); got != tc.want {
					t.Errorf("Reveal() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("uint32", func(t *testing.T) {
		tests := map[string]struct {
			input   []byte
			want    uint32
			wantErr bool
		}{
			"zero":        {input: []byte("0"), want: 0},
			"positive":    {input: []byte("1"), want: 1},
			"max":         {input: []byte("4294967295"), want: math.MaxUint32},
			"overflow":    {input: []byte("4294967296"), wantErr: true},
			"negative":    {input: []byte("-1"), wantErr: true},
			"non-numeric": {input: []byte("abc"), wantErr: true},
			"empty":       {input: []byte(""), wantErr: true},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				var s Value[uint32]
				err := s.UnmarshalText(tc.input)
				if tc.wantErr {
					if !errors.Is(err, ErrParseFailed) {
						t.Fatalf("want ErrParseFailed, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got := s.Reveal(); got != tc.want {
					t.Errorf("Reveal() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("uint64", func(t *testing.T) {
		tests := map[string]struct {
			input   []byte
			want    uint64
			wantErr bool
		}{
			"zero":        {input: []byte("0"), want: 0},
			"positive":    {input: []byte("42"), want: 42},
			"max":         {input: []byte("18446744073709551615"), want: math.MaxUint64},
			"overflow":    {input: []byte("18446744073709551616"), wantErr: true},
			"negative":    {input: []byte("-1"), wantErr: true},
			"non-numeric": {input: []byte("abc"), wantErr: true},
			"float":       {input: []byte("1.5"), wantErr: true},
			"empty":       {input: []byte(""), wantErr: true},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				var s Value[uint64]
				err := s.UnmarshalText(tc.input)
				if tc.wantErr {
					if !errors.Is(err, ErrParseFailed) {
						t.Fatalf("want ErrParseFailed, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got := s.Reveal(); got != tc.want {
					t.Errorf("Reveal() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("float32", func(t *testing.T) {
		tests := map[string]struct {
			input   []byte
			want    float32
			wantErr bool
		}{
			"zero":                    {input: []byte("0"), want: 0},
			"positive":                {input: []byte("1"), want: 1},
			"negative":                {input: []byte("-1"), want: -1},
			"decimal":                 {input: []byte("1.5"), want: 1.5},
			"max":                     {input: []byte(strconv.FormatFloat(math.MaxFloat32, 'g', -1, 32)), want: math.MaxFloat32},
			"smallest nonzero":        {input: []byte(strconv.FormatFloat(math.SmallestNonzeroFloat32, 'g', -1, 32)), want: math.SmallestNonzeroFloat32},
			"positive infinity":       {input: []byte("+Inf"), want: float32(math.Inf(1))},
			"negative infinity":       {input: []byte("-Inf"), want: float32(math.Inf(-1))},
			"overflow beyond float32": {input: []byte("3.5e38"), wantErr: true},
			"non-numeric":             {input: []byte("abc"), wantErr: true},
			"empty":                   {input: []byte(""), wantErr: true},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				var s Value[float32]
				err := s.UnmarshalText(tc.input)
				if tc.wantErr {
					if !errors.Is(err, ErrParseFailed) {
						t.Fatalf("want ErrParseFailed, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got := s.Reveal(); got != tc.want {
					t.Errorf("Reveal() = %v, want %v", got, tc.want)
				}
			})
		}
		t.Run("NaN", func(t *testing.T) {
			var s Value[float32]
			if err := s.UnmarshalText([]byte("NaN")); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !math.IsNaN(float64(s.Reveal())) {
				t.Errorf("Reveal() = %v, want NaN", s.Reveal())
			}
		})
	})

	t.Run("time.Duration", func(t *testing.T) {
		tests := map[string]struct {
			input   []byte
			want    time.Duration
			wantErr bool
		}{
			"zero":         {input: []byte("0s"), want: 0},
			"seconds":      {input: []byte("30s"), want: 30 * time.Second},
			"minutes":      {input: []byte("5m"), want: 5 * time.Minute},
			"hours":        {input: []byte("2h"), want: 2 * time.Hour},
			"compound":     {input: []byte("1h30m"), want: time.Hour + 30*time.Minute},
			"milliseconds": {input: []byte("500ms"), want: 500 * time.Millisecond},
			"microseconds": {input: []byte("100us"), want: 100 * time.Microsecond},
			"nanoseconds":  {input: []byte("1ns"), want: time.Nanosecond},
			"negative":     {input: []byte("-1h"), want: -time.Hour},
			"fractional":   {input: []byte("1.5s"), want: 1500 * time.Millisecond},
			"non-duration": {input: []byte("abc"), wantErr: true},
			"bare number":  {input: []byte("42"), wantErr: true},
			"empty":        {input: []byte(""), wantErr: true},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				var s Value[time.Duration]
				err := s.UnmarshalText(tc.input)
				if tc.wantErr {
					if !errors.Is(err, ErrParseFailed) {
						t.Fatalf("want ErrParseFailed, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got := s.Reveal(); got != tc.want {
					t.Errorf("Reveal() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("time.Duration value not mutated on error", func(t *testing.T) {
		s := Redact(5 * time.Second)
		if err := s.UnmarshalText([]byte("abc")); !errors.Is(err, ErrParseFailed) {
			t.Fatalf("expected ErrParseFailed, got %v", err)
		}
		if got := s.Reveal(); got != 5*time.Second {
			t.Errorf("value mutated on error: got %v, want %v", got, 5*time.Second)
		}
	})

	t.Run("url.URL", func(t *testing.T) {
		tests := map[string]struct {
			input   []byte
			want    string
			wantErr bool
		}{
			"absolute URL":           {input: []byte("https://example.com"), want: "https://example.com"},
			"with path and query":    {input: []byte("https://example.com/path?q=1"), want: "https://example.com/path?q=1"},
			"with fragment":          {input: []byte("https://example.com/path#frag"), want: "https://example.com/path#frag"},
			"with userinfo and port": {input: []byte("http://user:pass@host:8080/path"), want: "http://user:pass@host:8080/path"},
			"relative path":          {input: []byte("/relative/path"), want: "/relative/path"},
			"empty":                  {input: []byte(""), want: ""},
			"invalid percent":        {input: []byte("%zz"), wantErr: true},
			"malformed IPv6":         {input: []byte("http://[::1"), wantErr: true},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				var s Value[url.URL]
				err := s.UnmarshalText(tc.input)
				if tc.wantErr {
					if !errors.Is(err, ErrParseFailed) {
						t.Fatalf("want ErrParseFailed, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				got := s.Reveal()
				if got.String() != tc.want {
					t.Errorf("Reveal().String() = %q, want %q", got.String(), tc.want)
				}
			})
		}
	})

	t.Run("url.URL value not mutated on error", func(t *testing.T) {
		original, _ := url.Parse("https://original.com")
		s := Redact(*original)
		if err := s.UnmarshalText([]byte("http://[::1")); !errors.Is(err, ErrParseFailed) {
			t.Fatalf("expected ErrParseFailed, got %v", err)
		}
		got := s.Reveal()
		if got.String() != "https://original.com" {
			t.Errorf("value mutated on error: got %q, want %q", got.String(), "https://original.com")
		}
	})

	t.Run("float64", func(t *testing.T) {
		tests := map[string]struct {
			input   []byte
			want    float64
			wantErr bool
		}{
			"zero":              {input: []byte("0"), want: 0},
			"positive":          {input: []byte("1"), want: 1},
			"negative":          {input: []byte("-1"), want: -1},
			"decimal":           {input: []byte("1.5"), want: 1.5},
			"max":               {input: []byte(strconv.FormatFloat(math.MaxFloat64, 'g', -1, 64)), want: math.MaxFloat64},
			"smallest nonzero":  {input: []byte(strconv.FormatFloat(math.SmallestNonzeroFloat64, 'g', -1, 64)), want: math.SmallestNonzeroFloat64},
			"positive infinity": {input: []byte("+Inf"), want: math.Inf(1)},
			"negative infinity": {input: []byte("-Inf"), want: math.Inf(-1)},
			"overflow":          {input: []byte("2e308"), wantErr: true},
			"non-numeric":       {input: []byte("abc"), wantErr: true},
			"empty":             {input: []byte(""), wantErr: true},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				var s Value[float64]
				err := s.UnmarshalText(tc.input)
				if tc.wantErr {
					if !errors.Is(err, ErrParseFailed) {
						t.Fatalf("want ErrParseFailed, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got := s.Reveal(); got != tc.want {
					t.Errorf("Reveal() = %v, want %v", got, tc.want)
				}
			})
		}
		t.Run("NaN", func(t *testing.T) {
			var s Value[float64]
			if err := s.UnmarshalText([]byte("NaN")); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !math.IsNaN(s.Reveal()) {
				t.Errorf("Reveal() = %v, want NaN", s.Reveal())
			}
		})
	})
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
	_ encoding.TextUnmarshaler = &Value[string]{}
)
