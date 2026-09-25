package config

import (
	"encoding/json"
	"testing"
)

// The v0.4 keys are release-ordered: a policy containing any of them makes an
// older binary exit 3, so the defaults (and therefore init) must never write
// them, and a policy without them must decode exactly as before.
func TestDefaultsWriteNoReleaseOrderedKeys(t *testing.T) {
	for _, lang := range []string{"go", "typescript", "javascript", "python", "unknown"} {
		c := Default(lang)
		if c.Fuzz != nil || c.Mutation != nil || c.Prepare != nil {
			t.Fatalf("Default(%q) sets a v0.4 key: %+v %+v %+v", lang, c.Fuzz, c.Mutation, c.Prepare)
		}
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(b, &keys); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"fuzz", "mutation", "prepare"} {
			if _, ok := keys[key]; ok {
				t.Errorf("Default(%q) marshals %q", lang, key)
			}
		}
		if len(keys) != 6 {
			t.Errorf("Default(%q) marshals %d top-level keys, want the 6 existing ones", lang, len(keys))
		}
	}
}

// A policy with all three keys round-trips through Decode, and nil-safe
// validation leaves an unconfigured policy untouched.
func TestReleaseOrderedKeysRoundTrip(t *testing.T) {
	c := Default("go")
	c.Fuzz = &Fuzz{MaxInputs: 16}
	c.Mutation = &Mutation{Command: []string{"go", "test", "-json", "{package}"}, MaxMutants: 5, TimeoutSeconds: 30, MaxRuntimeSeconds: 120}
	c.Prepare = &Prepare{Command: []string{"go", "mod", "download"}, Inputs: []string{"go.mod", "go.sum"}, Env: map[string]string{"GOFLAGS": "-mod=mod"}}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatalf("configured policy rejected: %v", err)
	}
	if got.Fuzz == nil || got.Fuzz.MaxInputs != 16 || got.Mutation == nil || got.Mutation.MaxMutants != 5 || got.Prepare == nil || got.Prepare.Env["GOFLAGS"] != "-mod=mod" {
		t.Fatalf("round trip lost a key: %+v %+v %+v", got.Fuzz, got.Mutation, got.Prepare)
	}
	var nilFuzz *Fuzz
	var nilMutation *Mutation
	var nilPrepare *Prepare
	s := Default("go").Sandbox
	if nilFuzz.validate(s) != nil || nilMutation.validate(s) != nil || nilPrepare.validate(s) != nil {
		t.Fatal("nil policy objects must validate")
	}
}
