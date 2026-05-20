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

	"github.com/saas-craft/typedenv"
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
	t.Run("string", func(t *testing.T) {
		for _, secret := range []string{"my-secret-value", "a", ""} {
			if got := Redact(secret).Reveal(); got != secret {
				t.Errorf("Reveal() = %q, want %q", got, secret)
			}
		}
	})
	t.Run("int", func(t *testing.T) {
		for _, v := range []int{42, -1, 0} {
			if got := Redact(v).Reveal(); got != v {
				t.Errorf("Reveal() = %v, want %v", got, v)
			}
		}
	})
}

func TestRedaction(t *testing.T) {
	s := Redact("my-secret-value")

	t.Run("String", func(t *testing.T) {
		if got := s.String(); got != redacted {
			t.Errorf("got %q, want %q", got, redacted)
		}
	})
	t.Run("GoString", func(t *testing.T) {
		if got := s.GoString(); got != redacted {
			t.Errorf("got %q, want %q", got, redacted)
		}
	})
	t.Run("MarshalJSON", func(t *testing.T) {
		data, err := s.MarshalJSON()
		if !errors.Is(err, ErrUseOfRedacted) {
			t.Fatalf("want ErrUseOfRedacted, got %v", err)
		}
		if data != nil {
			t.Errorf("want nil data, got %s", data)
		}
	})
	t.Run("MarshalText", func(t *testing.T) {
		data, err := s.MarshalText()
		if !errors.Is(err, ErrUseOfRedacted) {
			t.Fatalf("want ErrUseOfRedacted, got %v", err)
		}
		if data != nil {
			t.Errorf("want nil data, got %q", data)
		}
	})
	t.Run("MarshalBinary", func(t *testing.T) {
		data, err := s.MarshalBinary()
		if !errors.Is(err, ErrUseOfRedacted) {
			t.Fatalf("want ErrUseOfRedacted, got %v", err)
		}
		if data != nil {
			t.Errorf("want nil data, got %q", data)
		}
	})
	t.Run("Value", func(t *testing.T) {
		val, err := s.Value()
		if !errors.Is(err, ErrUseOfRedacted) {
			t.Fatalf("want ErrUseOfRedacted, got %v", err)
		}
		if val != nil {
			t.Errorf("want nil value, got %v", val)
		}
	})
	t.Run("LogValue", func(t *testing.T) {
		val := s.LogValue()
		if val.Kind() != slog.KindString {
			t.Errorf("want KindString, got %v", val.Kind())
		}
		if val.String() != redacted {
			t.Errorf("got %q, want %q", val.String(), redacted)
		}
	})
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

func checkUnmarshal[T comparable](t *testing.T, input []byte, want T, wantErr bool) {
	t.Helper()
	var s Value[T]
	err := s.UnmarshalText(input)
	if wantErr {
		if !errors.Is(err, ErrParseFailed) {
			t.Fatalf("want ErrParseFailed, got %v", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := s.Reveal(); got != want {
		t.Errorf("Reveal() = %v, want %v", got, want)
	}
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
				checkUnmarshal(t, tc.input, tc.want, false)
			})
		}
	})

	t.Run("TextUnmarshaler populates fields correctly", func(t *testing.T) {
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

	t.Run("unsupported struct type returns ErrUnsupportedType", func(t *testing.T) {
		type opaque struct{ val string }
		var s Value[opaque]
		if err := s.UnmarshalText([]byte("anything")); !errors.Is(err, ErrUnsupportedType) {
			t.Fatalf("want ErrUnsupportedType, got %v", err)
		}
	})

	t.Run("unsupported kind returns ErrUnsupportedType", func(t *testing.T) {
		type mySlice []byte
		var s Value[mySlice]
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
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
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
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
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
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
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
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
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
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
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
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
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
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
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
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
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
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
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
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
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
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
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
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
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
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
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
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
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

	// Named types — verify kind dispatch fires for type aliases.

	t.Run("named string type", func(t *testing.T) {
		type myString string
		tests := map[string]struct {
			input []byte
			want  myString
		}{
			"non-empty": {input: []byte("hello"), want: "hello"},
			"empty":     {input: []byte{}, want: ""},
			"nil":       {input: nil, want: ""},
		}
		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				checkUnmarshal(t, tc.input, tc.want, false)
			})
		}
	})

	t.Run("named bool type", func(t *testing.T) {
		type myBool bool
		tests := map[string]struct {
			input   []byte
			want    myBool
			wantErr bool
		}{
			"true":    {input: []byte("true"), want: true},
			"false":   {input: []byte("false"), want: false},
			"invalid": {input: []byte("yes"), wantErr: true},
		}
		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
			})
		}
		t.Run("value not mutated on error", func(t *testing.T) {
			s := Redact(myBool(true))
			if err := s.UnmarshalText([]byte("invalid")); !errors.Is(err, ErrParseFailed) {
				t.Fatalf("expected ErrParseFailed, got %v", err)
			}
			if got := s.Reveal(); got != true {
				t.Errorf("value mutated on error: got %v, want true", got)
			}
		})
	})

	t.Run("named int type", func(t *testing.T) {
		type myInt int
		tests := map[string]struct {
			input   []byte
			want    myInt
			wantErr bool
		}{
			"positive":    {input: []byte("42"), want: 42},
			"non-numeric": {input: []byte("abc"), wantErr: true},
		}
		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
			})
		}
		t.Run("value not mutated on error", func(t *testing.T) {
			s := Redact(myInt(99))
			if err := s.UnmarshalText([]byte("bad")); !errors.Is(err, ErrParseFailed) {
				t.Fatalf("expected ErrParseFailed, got %v", err)
			}
			if got := s.Reveal(); got != 99 {
				t.Errorf("value mutated on error: got %v, want 99", got)
			}
		})
	})

	t.Run("named int8 type", func(t *testing.T) {
		type myInt8 int8
		tests := map[string]struct {
			input   []byte
			want    myInt8
			wantErr bool
		}{
			"max":      {input: []byte("127"), want: 127},
			"overflow": {input: []byte("128"), wantErr: true},
		}
		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
			})
		}
	})

	t.Run("named int16 type", func(t *testing.T) {
		type myInt16 int16
		tests := map[string]struct {
			input   []byte
			want    myInt16
			wantErr bool
		}{
			"max":      {input: []byte("32767"), want: 32767},
			"overflow": {input: []byte("32768"), wantErr: true},
		}
		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
			})
		}
	})

	t.Run("named int32 type", func(t *testing.T) {
		type myInt32 int32
		tests := map[string]struct {
			input   []byte
			want    myInt32
			wantErr bool
		}{
			"max":      {input: []byte("2147483647"), want: 2147483647},
			"overflow": {input: []byte("2147483648"), wantErr: true},
		}
		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
			})
		}
	})

	t.Run("named int64 type", func(t *testing.T) {
		type myInt64 int64
		tests := map[string]struct {
			input   []byte
			want    myInt64
			wantErr bool
		}{
			"max":      {input: []byte("9223372036854775807"), want: 9223372036854775807},
			"overflow": {input: []byte("9223372036854775808"), wantErr: true},
		}
		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
			})
		}
	})

	t.Run("named uint type", func(t *testing.T) {
		type myUint uint
		tests := map[string]struct {
			input   []byte
			want    myUint
			wantErr bool
		}{
			"positive": {input: []byte("42"), want: 42},
			"negative": {input: []byte("-1"), wantErr: true},
		}
		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
			})
		}
		t.Run("value not mutated on error", func(t *testing.T) {
			s := Redact(myUint(7))
			if err := s.UnmarshalText([]byte("-1")); !errors.Is(err, ErrParseFailed) {
				t.Fatalf("expected ErrParseFailed, got %v", err)
			}
			if got := s.Reveal(); got != 7 {
				t.Errorf("value mutated on error: got %v, want 7", got)
			}
		})
	})

	t.Run("named uint8 type", func(t *testing.T) {
		type myUint8 uint8
		tests := map[string]struct {
			input   []byte
			want    myUint8
			wantErr bool
		}{
			"max":      {input: []byte("255"), want: 255},
			"overflow": {input: []byte("256"), wantErr: true},
		}
		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
			})
		}
	})

	t.Run("named uint16 type", func(t *testing.T) {
		type myUint16 uint16
		tests := map[string]struct {
			input   []byte
			want    myUint16
			wantErr bool
		}{
			"max":      {input: []byte("65535"), want: 65535},
			"overflow": {input: []byte("65536"), wantErr: true},
		}
		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
			})
		}
	})

	t.Run("named uint32 type", func(t *testing.T) {
		type myUint32 uint32
		tests := map[string]struct {
			input   []byte
			want    myUint32
			wantErr bool
		}{
			"max":      {input: []byte("4294967295"), want: 4294967295},
			"overflow": {input: []byte("4294967296"), wantErr: true},
		}
		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
			})
		}
	})

	t.Run("named uint64 type", func(t *testing.T) {
		type myUint64 uint64
		tests := map[string]struct {
			input   []byte
			want    myUint64
			wantErr bool
		}{
			"max":      {input: []byte("18446744073709551615"), want: 18446744073709551615},
			"overflow": {input: []byte("18446744073709551616"), wantErr: true},
		}
		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
			})
		}
	})

	t.Run("named float32 type", func(t *testing.T) {
		type myFloat32 float32
		tests := map[string]struct {
			input   []byte
			want    myFloat32
			wantErr bool
		}{
			"positive": {input: []byte("1.5"), want: 1.5},
			"overflow": {input: []byte("3.5e38"), wantErr: true},
		}
		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
			})
		}
		t.Run("value not mutated on error", func(t *testing.T) {
			s := Redact(myFloat32(3.14))
			if err := s.UnmarshalText([]byte("bad")); !errors.Is(err, ErrParseFailed) {
				t.Fatalf("expected ErrParseFailed, got %v", err)
			}
			if got := s.Reveal(); got != 3.14 {
				t.Errorf("value mutated on error: got %v, want 3.14", got)
			}
		})
	})

	t.Run("named float64 type", func(t *testing.T) {
		type myFloat64 float64
		tests := map[string]struct {
			input   []byte
			want    myFloat64
			wantErr bool
		}{
			"positive": {input: []byte("1.5"), want: 1.5},
			"overflow": {input: []byte("2e308"), wantErr: true},
		}
		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				checkUnmarshal(t, tc.input, tc.want, tc.wantErr)
			})
		}
		t.Run("NaN", func(t *testing.T) {
			var s Value[myFloat64]
			if err := s.UnmarshalText([]byte("NaN")); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !math.IsNaN(float64(s.Reveal())) {
				t.Errorf("Reveal() = %v, want NaN", s.Reveal())
			}
		})
		t.Run("value not mutated on error", func(t *testing.T) {
			s := Redact(myFloat64(2.71))
			if err := s.UnmarshalText([]byte("bad")); !errors.Is(err, ErrParseFailed) {
				t.Fatalf("expected ErrParseFailed, got %v", err)
			}
			if got := s.Reveal(); got != 2.71 {
				t.Errorf("value mutated on error: got %v, want 2.71", got)
			}
		})
	})

	t.Run("named url.URL type", func(t *testing.T) {
		type myURL url.URL
		tests := map[string]struct {
			input   []byte
			want    string
			wantErr bool
		}{
			"absolute URL":    {input: []byte("https://example.com"), want: "https://example.com"},
			"invalid percent": {input: []byte("%zz"), wantErr: true},
		}
		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				var s Value[myURL]
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
				got := url.URL(s.Reveal())
				if got.String() != tc.want {
					t.Errorf("Reveal().String() = %q, want %q", got.String(), tc.want)
				}
			})
		}
		t.Run("value not mutated on error", func(t *testing.T) {
			original, _ := url.Parse("https://original.com")
			s := Redact(myURL(*original))
			if err := s.UnmarshalText([]byte("http://[::1")); !errors.Is(err, ErrParseFailed) {
				t.Fatalf("expected ErrParseFailed, got %v", err)
			}
			got := url.URL(s.Reveal())
			if got.String() != "https://original.com" {
				t.Errorf("value mutated on error: got %q, want %q", got.String(), "https://original.com")
			}
		})
	})
}

func TestTypedenvIntegration(t *testing.T) {
	type config struct {
		Host    Value[string]        `env:"HOST"`
		Port    Value[uint16]        `env:"PORT"`
		Timeout Value[time.Duration] `env:"TIMEOUT"`
	}

	t.Setenv("HOST", "api.saascraft.com")
	t.Setenv("PORT", "9000")
	t.Setenv("TIMEOUT", "5s")

	cfg, err := typedenv.Load[config]()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("values are revealed correctly", func(t *testing.T) {
		if got := cfg.Host.Reveal(); got != "api.saascraft.com" {
			t.Errorf("Host.Reveal() = %q, want %q", got, "api.saascraft.com")
		}
		if got := cfg.Port.Reveal(); got != uint16(9000) {
			t.Errorf("Port.Reveal() = %v, want %v", got, uint16(9000))
		}
		if got := cfg.Timeout.Reveal(); got != 5*time.Second {
			t.Errorf("Timeout.Reveal() = %v, want %v", got, 5*time.Second)
		}
	})

	t.Run("values are redacted when formatted", func(t *testing.T) {
		want := "{Host:[REDACTED] Port:[REDACTED] Timeout:[REDACTED]}"
		if got := fmt.Sprintf("%+v", cfg); got != want {
			t.Errorf("Sprintf(%%+v) = %q, want %q", got, want)
		}
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
