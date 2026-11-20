package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"testing"
)

func TestRedactionEverywhere(t *testing.T) {
	v := New("super-secret-value")
	if got := v.String(); got != "<redacted>" {
		t.Fatalf("String leaked: %q", got)
	}
	if got := fmt.Sprintf("%v|%s|%+v|%#v|%q", v, v, v, v, v); strings.Contains(got, "super-secret") {
		t.Fatalf("format leaked: %q", got)
	}
	j, err := json.Marshal(struct{ V Value }{v})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(j, []byte("super-secret")) {
		t.Fatalf("json leaked: %s", j)
	}
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	logger.Printf("value=%v", v)
	if strings.Contains(buf.String(), "super-secret") {
		t.Fatalf("log leaked: %s", buf.String())
	}
	var parsed Value
	if err := json.Unmarshal([]byte(`"x"`), &parsed); err == nil {
		t.Fatal("expected unmarshal rejection")
	}
}

func TestRevealReturnsCopy(t *testing.T) {
	v := New("abc")
	b := v.Reveal()
	b[0] = 'z'
	if v.EqualString("abc") != true {
		t.Fatal("secret mutated through revealed copy")
	}
	if !v.Equal(New("abc")) || v.EqualString("abd") {
		t.Fatal("comparison wrong")
	}
	v.Clear()
	if v.Len() != 0 {
		t.Fatal("clear failed")
	}
}
