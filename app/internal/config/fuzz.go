package config

import "fmt"

// Defaults of the optional fuzz policy object. A field left at 0 takes its
// default; the default runtime is additionally clamped to the sandbox budget.
const (
	DefaultFuzzFunctions      = 8
	DefaultFuzzPackages       = 4
	DefaultFuzzInputs         = 64
	DefaultFuzzCallTimeoutMS  = 1000
	DefaultFuzzRuntimeSeconds = 240
)

// Fuzz enables deterministic differential fuzzing of changed Go functions. It is
// opt-in and release-ordered: a policy that contains it makes every binary
// before v0.4.0 exit 3, so Default (and therefore init) never writes it.
//
// "fuzz": {} enables fuzzing with the defaults; an absent key or null leaves the
// pointer nil and fuzzing off. max_runtime_seconds is a sub-cap inside the shared
// sandbox runtime budget, never an addition to it.
type Fuzz struct {
	MaxFunctions      int `json:"max_functions"`
	MaxPackages       int `json:"max_packages"`
	MaxInputs         int `json:"max_inputs"`
	CallTimeoutMS     int `json:"call_timeout_ms"`
	MaxRuntimeSeconds int `json:"max_runtime_seconds"`
}

// validate is nil-safe: a nil receiver means fuzzing is not configured. Each
// field is 0 (the default) or within its bounds; explicit time limits must also
// fit inside the sandbox limits.
func (f *Fuzz) validate(s Sandbox) error {
	if f == nil {
		return nil
	}
	for _, field := range []struct {
		name     string
		value    int
		min, max int
	}{
		{"max_functions", f.MaxFunctions, 1, 32},
		{"max_packages", f.MaxPackages, 1, 16},
		{"max_inputs", f.MaxInputs, 1, 256},
		{"call_timeout_ms", f.CallTimeoutMS, 10, 10000},
		{"max_runtime_seconds", f.MaxRuntimeSeconds, 1, 7200},
	} {
		if field.value != 0 && (field.value < field.min || field.value > field.max) {
			return fmt.Errorf("fuzz.%s must be 0 (the default) or between %d and %d", field.name, field.min, field.max)
		}
	}
	if f.CallTimeoutMS != 0 && f.CallTimeoutMS > s.TimeoutSeconds*1000 {
		return fmt.Errorf("fuzz.call_timeout_ms must not exceed sandbox.timeout_seconds (%d ms)", s.TimeoutSeconds*1000)
	}
	if f.MaxRuntimeSeconds != 0 && f.MaxRuntimeSeconds > s.MaxRuntimeSeconds {
		return fmt.Errorf("fuzz.max_runtime_seconds must not exceed sandbox.max_runtime_seconds (%d)", s.MaxRuntimeSeconds)
	}
	return nil
}

// Effective returns the resolved limits: every 0 becomes its default, and a
// defaulted runtime is clamped to min(240, sandbox.max_runtime_seconds). A nil
// receiver resolves to the defaults.
func (f *Fuzz) Effective(s Sandbox) Fuzz {
	var e Fuzz
	if f != nil {
		e = *f
	}
	if e.MaxFunctions == 0 {
		e.MaxFunctions = DefaultFuzzFunctions
	}
	if e.MaxPackages == 0 {
		e.MaxPackages = DefaultFuzzPackages
	}
	if e.MaxInputs == 0 {
		e.MaxInputs = DefaultFuzzInputs
	}
	if e.CallTimeoutMS == 0 {
		e.CallTimeoutMS = DefaultFuzzCallTimeoutMS
	}
	if e.MaxRuntimeSeconds == 0 {
		e.MaxRuntimeSeconds = DefaultFuzzRuntimeSeconds
		if s.MaxRuntimeSeconds > 0 && s.MaxRuntimeSeconds < e.MaxRuntimeSeconds {
			e.MaxRuntimeSeconds = s.MaxRuntimeSeconds
		}
	}
	return e
}
