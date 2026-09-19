package config

import (
	"encoding/json"
	"testing"
)

func TestRoundTripDefaults(t *testing.T) {
	for _, lang := range []string{"go", "typescript", "python", "unknown"} {
		c := Default(lang)
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(b)
		if err != nil {
			t.Fatal(err)
		}
		if got.Sandbox.Network {
			t.Fatal("network enabled by default")
		}
	}
}
func TestRejectInvalidPolicy(t *testing.T) {
	for _, input := range []string{
		`{"version":2}`, `{"version":1,"secret":"oops"}`, `{"version":1} {}`,
		`{"commands":{"test":"go test ./..."}}`, `{"commands":{"shell":["sh"]}}`,
		`{"sandbox":{"timeout_seconds":0}}`, `{"sandbox":{"image":"--privileged"}}`,
		`{"reviewer":{"max_iterations":100000}}`, `{"sensitive_paths":["../outside"]}`,
		`null`, `{"version":1,"version":2}`, `{"version":1,"Version":1}`,
		`{"sandbox":{"network":false,"network":true}}`,
	} {
		if _, err := Decode([]byte(input)); err == nil {
			t.Errorf("accepted %s", input)
		}
	}
}
