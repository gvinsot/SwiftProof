package config

import (
	"strings"
	"testing"
)

// policy decodes a version-1 policy made of the given top-level members.
func policy(members string) (Config, error) {
	return Decode([]byte(`{"version":1` + members + `}`))
}

func TestFuzzBoundsAtEdges(t *testing.T) {
	for _, tc := range []struct {
		members string
		ok      bool
	}{
		{`,"fuzz":{}`, true},
		{`,"fuzz":{"max_functions":0}`, true},
		{`,"fuzz":{"max_functions":1}`, true},
		{`,"fuzz":{"max_functions":32}`, true},
		{`,"fuzz":{"max_functions":33}`, false},
		{`,"fuzz":{"max_functions":-1}`, false},
		{`,"fuzz":{"max_packages":1}`, true},
		{`,"fuzz":{"max_packages":16}`, true},
		{`,"fuzz":{"max_packages":17}`, false},
		{`,"fuzz":{"max_packages":-1}`, false},
		{`,"fuzz":{"max_inputs":1}`, true},
		{`,"fuzz":{"max_inputs":256}`, true},
		{`,"fuzz":{"max_inputs":257}`, false},
		{`,"fuzz":{"max_inputs":-1}`, false},
		{`,"fuzz":{"call_timeout_ms":9}`, false},
		{`,"fuzz":{"call_timeout_ms":10}`, true},
		{`,"fuzz":{"call_timeout_ms":10000}`, true},
		{`,"fuzz":{"call_timeout_ms":10001}`, false},
		{`,"fuzz":{"call_timeout_ms":-1}`, false},
		// call_timeout_ms is also bounded by sandbox.timeout_seconds*1000.
		{`,"sandbox":{"timeout_seconds":5},"fuzz":{"call_timeout_ms":5000}`, true},
		{`,"sandbox":{"timeout_seconds":5},"fuzz":{"call_timeout_ms":5001}`, false},
		{`,"fuzz":{"max_runtime_seconds":1}`, true},
		{`,"fuzz":{"max_runtime_seconds":-1}`, false},
		// max_runtime_seconds is a sub-cap of sandbox.max_runtime_seconds (600 by default).
		{`,"fuzz":{"max_runtime_seconds":600}`, true},
		{`,"fuzz":{"max_runtime_seconds":601}`, false},
		{`,"sandbox":{"max_runtime_seconds":7200},"fuzz":{"max_runtime_seconds":7200}`, true},
		{`,"sandbox":{"max_runtime_seconds":7200},"fuzz":{"max_runtime_seconds":7201}`, false},
		{`,"fuzz":{"unknown":1}`, false},
		{`,"fuzz":{"max_inputs":1,"max_inputs":2}`, false},
		{`,"fuzz":{"max_inputs":1,"MAX_INPUTS":2}`, false},
		{`,"fuzz":[]`, false},
		{`,"fuzz":1`, false},
	} {
		_, err := policy(tc.members)
		if tc.ok && err != nil {
			t.Errorf("%s rejected: %v", tc.members, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s accepted", tc.members)
		}
	}
}

func TestFuzzNullIsAbsent(t *testing.T) {
	c, err := policy(`,"fuzz":null`)
	if err != nil || c.Fuzz != nil {
		t.Fatalf("null fuzz: %+v, %v", c.Fuzz, err)
	}
	c, err = policy(`,"fuzz":{}`)
	if err != nil || c.Fuzz == nil {
		t.Fatalf("empty fuzz object must enable fuzzing: %+v, %v", c.Fuzz, err)
	}
}

func TestFuzzEffective(t *testing.T) {
	sandbox := Default("go").Sandbox
	got := (&Fuzz{}).Effective(sandbox)
	want := Fuzz{MaxFunctions: 8, MaxPackages: 4, MaxInputs: 64, CallTimeoutMS: 1000, MaxRuntimeSeconds: 240}
	if got != want {
		t.Fatalf("defaults %+v, want %+v", got, want)
	}
	if got := (*Fuzz)(nil).Effective(sandbox); got != want {
		t.Fatalf("nil receiver %+v, want %+v", got, want)
	}
	sandbox.MaxRuntimeSeconds = 100
	if got := (&Fuzz{}).Effective(sandbox).MaxRuntimeSeconds; got != 100 {
		t.Fatalf("defaulted runtime %d, want it clamped to the sandbox budget 100", got)
	}
	explicit := Fuzz{MaxFunctions: 2, MaxPackages: 3, MaxInputs: 5, CallTimeoutMS: 50, MaxRuntimeSeconds: 60}
	if got := explicit.Effective(sandbox); got != explicit {
		t.Fatalf("explicit values changed: %+v", got)
	}
}

func TestFuzzErrorsNameTheField(t *testing.T) {
	_, err := policy(`,"fuzz":{"max_inputs":257}`)
	if err == nil || !strings.Contains(err.Error(), "fuzz.max_inputs") {
		t.Fatalf("error %v does not name fuzz.max_inputs", err)
	}
}
