package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// schemaPath is the public report schema, relative to this package directory.
var schemaPath = filepath.Join("..", "..", "schema", "confidence-report.schema.json")

// legacyOptionalRootFields are non-omitempty Report fields that the schema does
// not require at the root, so that reports written by earlier versions (which
// lack them) still validate. Every other non-omitempty field is required.
var legacyOptionalRootFields = map[string]bool{
	"policy":               true, // recorded since v0.2; absent from earlier reports
	"coverage":             true, // recorded since v0.2; absent from earlier reports
	"intent_criteria":      true, // v0.4 (§1.4: none of the new root fields is required)
	"divergences":          true, // v0.4
	"intent_test_failures": true, // v0.4
}

// schemaKeywords is every keyword the report schema may use. The structural
// test rejects anything else, so a misspelled constraint cannot be silently
// ignored by the stdlib validator in schema_validate_test.go.
var schemaKeywords = map[string]bool{
	"$schema": true, "$id": true, "$defs": true, "$ref": true, "title": true, "description": true,
	"type": true, "enum": true, "const": true, "format": true,
	"properties": true, "required": true, "additionalProperties": true,
	"items": true, "minItems": true, "maxItems": true, "uniqueItems": true,
	"minLength": true, "maxLength": true, "pattern": true, "minimum": true, "maximum": true,
	"allOf": true, "not": true, "if": true, "then": true, "else": true,
}

type schemaDoc struct {
	root map[string]any
	defs map[string]any
}

func loadSchema(t *testing.T) *schemaDoc {
	t.Helper()
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := rejectDuplicateKeys(data); err != nil {
		t.Fatalf("schema: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var root map[string]any
	if err := dec.Decode(&root); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	defs, ok := root["$defs"].(map[string]any)
	if !ok {
		t.Fatal("schema has no $defs object")
	}
	return &schemaDoc{root: root, defs: defs}
}

// rejectDuplicateKeys fails on a JSON object that repeats a key: encoding/json
// would silently keep the last one, hiding a conflicting definition.
func rejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var walk func(path string) error
	walk = func(path string) error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch tok {
		case json.Delim('{'):
			seen := map[string]bool{}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return err
				}
				key := keyTok.(string)
				if seen[key] {
					return fmt.Errorf("duplicate key %q at %s", key, path)
				}
				seen[key] = true
				if err := walk(path + "/" + key); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case json.Delim('['):
			for i := 0; dec.More(); i++ {
				if err := walk(fmt.Sprintf("%s/%d", path, i)); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		}
		return nil
	}
	if err := walk(""); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the schema document")
	}
	return nil
}

// resolve follows a chain of "$ref" pointers to $defs entries.
func (s *schemaDoc) resolve(node map[string]any) (map[string]any, error) {
	for i := 0; i < 16; i++ {
		ref, ok := node["$ref"].(string)
		if !ok {
			return node, nil
		}
		name, ok := strings.CutPrefix(ref, "#/$defs/")
		if !ok {
			return nil, fmt.Errorf("unsupported $ref %q", ref)
		}
		next, ok := s.defs[name].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("$ref %q does not resolve", ref)
		}
		node = next
	}
	return nil, errors.New("$ref chain too deep")
}

// objectDef returns the object definition a property schema designates: the
// node itself or its $ref target, or the single object member of an allOf
// (as in "allOf": [{"$ref": "#/$defs/hypothesis"}, {constraints}]).
func (s *schemaDoc) objectDef(node map[string]any) (map[string]any, error) {
	node, err := s.resolve(node)
	if err != nil {
		return nil, err
	}
	if _, ok := node["properties"]; ok && node["type"] == "object" {
		return node, nil
	}
	var found map[string]any
	if all, ok := node["allOf"].([]any); ok {
		for _, member := range all {
			m, ok := member.(map[string]any)
			if !ok {
				continue
			}
			m, err := s.resolve(m)
			if err != nil {
				return nil, err
			}
			if _, ok := m["properties"]; ok && m["type"] == "object" {
				if found != nil {
					return nil, errors.New("allOf holds more than one object definition")
				}
				found = m
			}
		}
	}
	if found == nil {
		return nil, errors.New("no object definition with properties")
	}
	return found, nil
}

// jsonType returns the JSON type a schema node constrains its instance to.
func (s *schemaDoc) jsonType(node map[string]any) (string, error) {
	node, err := s.resolve(node)
	if err != nil {
		return "", err
	}
	if t, ok := node["type"].(string); ok {
		return t, nil
	}
	valueType := func(v any) string {
		switch v.(type) {
		case string:
			return "string"
		case json.Number:
			return "integer"
		case bool:
			return "boolean"
		}
		return ""
	}
	if c, ok := node["const"]; ok {
		return valueType(c), nil
	}
	if e, ok := node["enum"].([]any); ok && len(e) > 0 {
		return valueType(e[0]), nil
	}
	if all, ok := node["allOf"].([]any); ok {
		for _, member := range all {
			if m, ok := member.(map[string]any); ok {
				if t, err := s.jsonType(m); err == nil && t != "" {
					return t, nil
				}
			}
		}
	}
	return "", errors.New("schema node has no type, const or enum")
}

type jsonField struct {
	name      string
	omitempty bool
	typ       reflect.Type
}

func jsonFields(t reflect.Type) []jsonField {
	var fields []jsonField
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if name == "" {
			name = f.Name
		}
		fields = append(fields, jsonField{name: name, omitempty: strings.Contains(","+opts+",", ",omitempty,"), typ: f.Type})
	}
	return fields
}

func requiredSet(def map[string]any) map[string]bool {
	set := map[string]bool{}
	if req, ok := def["required"].([]any); ok {
		for _, r := range req {
			if name, ok := r.(string); ok {
				set[name] = true
			}
		}
	}
	return set
}

var timeType = reflect.TypeOf(time.Time{})

// checkMirror asserts that the schema object def mirrors the Go struct: the
// same property set, every non-omitempty field required, every omitempty field
// optional, additionalProperties false, and compatible types. It recurses into
// every struct reachable from Report.
func (s *schemaDoc) checkMirror(t *testing.T, where string, typ reflect.Type, def map[string]any, root bool, seen map[string]bool) {
	t.Helper()
	if def["additionalProperties"] != false {
		t.Errorf("%s (%s): additionalProperties must be false", where, typ.Name())
	}
	props, _ := def["properties"].(map[string]any)
	required := requiredSet(def)
	fields := jsonFields(typ)
	names := map[string]bool{}
	for _, f := range fields {
		names[f.name] = true
		at := where + "." + f.name
		raw, ok := props[f.name]
		if !ok {
			t.Errorf("%s: model field %s.%s has no schema property", at, typ.Name(), f.name)
			continue
		}
		prop, ok := raw.(map[string]any)
		if !ok {
			t.Errorf("%s: schema property is not an object", at)
			continue
		}
		switch {
		case f.omitempty && required[f.name]:
			t.Errorf("%s: omitempty field is required by the schema", at)
		case !f.omitempty && !required[f.name] && !(root && legacyOptionalRootFields[f.name]):
			t.Errorf("%s: non-omitempty field is not required by the schema", at)
		}
		s.checkType(t, at, f.typ, prop, seen)
	}
	for name := range props {
		if !names[name] {
			t.Errorf("%s: schema property %q has no %s field", where, name, typ.Name())
		}
	}
	for name := range required {
		if !names[name] {
			t.Errorf("%s: schema requires %q, which %s does not have", where, name, typ.Name())
		}
	}
}

func (s *schemaDoc) checkType(t *testing.T, at string, typ reflect.Type, prop map[string]any, seen map[string]bool) {
	t.Helper()
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	got, err := s.jsonType(prop)
	if err != nil {
		t.Errorf("%s: %v", at, err)
		return
	}
	var want string
	switch {
	case typ == timeType:
		want = "string"
		if node, err := s.resolve(prop); err != nil || node["format"] != "date-time" {
			t.Errorf("%s: a time.Time field must be a date-time string", at)
		}
	case typ.Kind() == reflect.String:
		want = "string"
	case typ.Kind() == reflect.Bool:
		want = "boolean"
	case typ.Kind() >= reflect.Int && typ.Kind() <= reflect.Uint64:
		want = "integer"
	case typ.Kind() == reflect.Slice:
		want = "array"
	case typ.Kind() == reflect.Struct:
		want = "object"
	default:
		t.Errorf("%s: unsupported Go kind %s", at, typ.Kind())
		return
	}
	if got != want {
		t.Errorf("%s: schema type %q, Go type %s wants %q", at, got, typ, want)
		return
	}
	switch {
	case typ.Kind() == reflect.Struct && typ != timeType:
		def, err := s.objectDef(prop)
		if err != nil {
			t.Errorf("%s: %v", at, err)
			return
		}
		key := at + "|" + typ.String()
		if seen[key] {
			return
		}
		seen[key] = true
		s.checkMirror(t, at, typ, def, false, seen)
	case typ.Kind() == reflect.Slice:
		node, err := s.resolve(prop)
		if err != nil {
			t.Errorf("%s: %v", at, err)
			return
		}
		items, ok := node["items"].(map[string]any)
		if !ok {
			t.Errorf("%s: array property has no items schema", at)
			return
		}
		s.checkType(t, at+"[]", typ.Elem(), items, seen)
	}
}

// TestSchemaMirrorsModel asserts, by reflection over the json tags, that every
// model field reachable from Report has a schema property, that every
// non-omitempty field is required (the root exceptions are listed in
// legacyOptionalRootFields), that every omitempty field is optional, and that
// no schema object has a property the model lacks.
func TestSchemaMirrorsModel(t *testing.T) {
	s := loadSchema(t)
	if s.root["type"] != "object" {
		t.Fatal("the schema root must be an object")
	}
	s.checkMirror(t, "report", reflect.TypeOf(Report{}), s.root, true, map[string]bool{})

	required := requiredSet(s.root)
	fields := map[string]jsonField{}
	for _, f := range jsonFields(reflect.TypeOf(Report{})) {
		fields[f.name] = f
	}
	for name := range legacyOptionalRootFields {
		f, ok := fields[name]
		switch {
		case !ok:
			t.Errorf("legacy-optional root field %q is not a Report field", name)
		case f.omitempty:
			t.Errorf("legacy-optional root field %q is omitempty; drop it from the exception list", name)
		case required[name]:
			t.Errorf("legacy-optional root field %q is required; drop it from the exception list", name)
		}
	}
}

func schemaEnum(t *testing.T, s *schemaDoc, def, property string) []string {
	t.Helper()
	d, ok := s.defs[def].(map[string]any)
	if !ok {
		t.Fatalf("$defs.%s is missing", def)
	}
	props, _ := d["properties"].(map[string]any)
	p, ok := props[property].(map[string]any)
	if !ok {
		t.Fatalf("$defs.%s.properties.%s is missing", def, property)
	}
	p, err := s.resolve(p)
	if err != nil {
		t.Fatal(err)
	}
	var values []string
	if c, ok := p["const"].(string); ok {
		values = append(values, c)
	}
	if e, ok := p["enum"].([]any); ok {
		for _, v := range e {
			str, ok := v.(string)
			if !ok {
				t.Fatalf("$defs.%s.%s: enum value %v is not a string", def, property, v)
			}
			values = append(values, str)
		}
	}
	if len(values) == 0 {
		t.Fatalf("$defs.%s.%s has no enum or const", def, property)
	}
	sort.Strings(values)
	return values
}

func sortedCopy(values ...string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

// TestSchemaEnumsMatchStatusConstants asserts that the shared hypothesis-status,
// evidence-status and evidence-kind enums equal the status.go constants exactly.
// Signal, artifact and check kinds are free strings and are not checked.
func TestSchemaEnumsMatchStatusConstants(t *testing.T) {
	s := loadSchema(t)
	shared := []struct {
		def, property string
		want          []string
	}{
		{"hypothesis", "status", []string{StatusReproduced, StatusDiverged, StatusIntentTestFailed, StatusNotReproduced, StatusDismissed, StatusUnverified}},
		{"evidence", "status", []string{
			StatusObserved, StatusReproduced, StatusNotReproduced, StatusUnverified, StatusDiverged, StatusNotDiverged,
			StatusFailsOnCandidate, StatusPassesOnCandidate, StatusIntentTestFailed, StatusIntentTestPassed,
		}},
		{"evidence", "kind", []string{
			EvidenceSourceObservation, EvidenceDifferentialTest, EvidenceDifferentialObservation, EvidenceDifferentialFuzz,
			EvidenceBaseTestDifferential, EvidenceImpactedTestDifferential, EvidenceIntentTest,
		}},
	}
	for _, tc := range shared {
		got, want := schemaEnum(t, s, tc.def, tc.property), sortedCopy(tc.want...)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("$defs.%s.%s enum = %v, want exactly the status.go constants %v", tc.def, tc.property, got, want)
		}
	}
}

// TestSchemaEnumsContainFeatureConstants asserts that the constants of the
// feature model files appear in the matching feature $defs enums. Owners may
// widen an enum together with its constants.
func TestSchemaEnumsContainFeatureConstants(t *testing.T) {
	s := loadSchema(t)
	cases := []struct {
		def, property string
		constants     []string
	}{
		{"policy", "source", []string{PolicyBaseRef, PolicyExplicit, PolicyDefault}},
		{"hypothesis", "intent_judgment", []string{JudgmentExpectedChange, JudgmentUnexpectedChange}},
		{"observation", "status", []string{ObservationEqual, ObservationDiverged, ObservationUnstable, ObservationIncomparable}},
		{"divergence", "kind", []string{EvidenceDifferentialObservation, EvidenceDifferentialFuzz}},
		{"fuzz", "status", []string{FuzzRan, FuzzNoCandidates, FuzzNotRun, FuzzDisabled}},
		{"fuzz", "seed_scheme", []string{FuzzSeedScheme}},
		{"fuzzFunction", "outcome", []string{FuzzDiverged, FuzzNotDiverged, FuzzInconclusive}},
		{"baseTests", "status", []string{BaseTestsNoCandidates, BaseTestsRan, BaseTestsNotRun}},
		{"baseTest", "change", []string{BaseTestRemoved, BaseTestModified, BaseTestSharedCodeChanged, BaseTestFileDeleted}},
		{"baseTest", "status", []string{StatusFailsOnCandidate, StatusPassesOnCandidate, StatusUnverified}},
		{"mutation", "status", []string{MutationNotRun, MutationNoCandidates, MutationRan, MutationIncomplete}},
		{"mutationFile", "status", []string{MutationFileEligible, MutationFileSkipped}},
		{"mutant", "status", []string{MutantKilled, MutantSurvived, MutantInvalid, MutantTimeout, MutantInconclusive, MutantNotRun}},
		{"impact", "status", []string{ImpactNotApplicable, ImpactIndexed, ImpactLimited, ImpactUnavailable}},
		{"impact", "tests_status", []string{ImpactTestsRan, ImpactTestsNoCandidates, ImpactTestsNotRun}},
		{"impactFunction", "change", []string{ChangeBodyChanged, ChangeSignatureChanged}},
		{"impactCaller", "resolution", []string{ResolutionStatic, ResolutionInterface}},
		{"impactTest", "resolution", []string{ResolutionStatic, ResolutionInterface}},
		{"impactTest", "status", []string{StatusFailsOnCandidate, StatusPassesOnCandidate, StatusUnverified}},
		{"checkCache", "status", []string{CacheHit, CacheStored}},
		{"executionCache", "status", []string{CacheEnabled, CacheDisabled}},
		{"executionCache", "scope", []string{CacheScopeBaseline}},
		{"prepare", "status", []string{PrepareBuilt, PrepareReused, PrepareFailed, PrepareNotPermitted, PrepareNotRun}},
	}
	for _, tc := range cases {
		enum := map[string]bool{}
		for _, v := range schemaEnum(t, s, tc.def, tc.property) {
			enum[v] = true
		}
		for _, c := range tc.constants {
			if !enum[c] {
				t.Errorf("$defs.%s.%s does not accept the model constant %q", tc.def, tc.property, c)
			}
		}
	}
}

// TestSchemaStructure checks the whole document: only known keywords, every
// $ref resolves, every pattern compiles, and every "required" name of an object
// definition names one of its properties.
func TestSchemaStructure(t *testing.T) {
	s := loadSchema(t)
	var walk func(at string, node any)
	walk = func(at string, node any) {
		switch n := node.(type) {
		case []any:
			for i, v := range n {
				walk(fmt.Sprintf("%s/%d", at, i), v)
			}
		case map[string]any:
			for key, v := range n {
				if !schemaKeywords[key] {
					t.Errorf("%s: unsupported schema keyword %q", at, key)
				}
				switch key {
				case "$defs", "properties":
					sub, ok := v.(map[string]any)
					if !ok {
						t.Errorf("%s/%s must be an object", at, key)
						continue
					}
					for name, def := range sub {
						walk(at+"/"+key+"/"+name, def)
					}
				case "enum", "const", "required", "description", "title", "$schema", "$id", "format", "type":
				case "$ref":
					if _, err := s.resolve(map[string]any{"$ref": v}); err != nil {
						t.Errorf("%s: %v", at, err)
					}
				case "pattern":
					if _, err := regexp.Compile(fmt.Sprint(v)); err != nil {
						t.Errorf("%s: pattern does not compile: %v", at, err)
					}
				default:
					walk(at+"/"+key, v)
				}
			}
			// Only object definitions: a conditional "then" may require
			// properties that its own partial "properties" does not repeat.
			if props, ok := n["properties"].(map[string]any); ok && n["type"] == "object" {
				for name := range requiredSet(n) {
					if _, ok := props[name]; !ok {
						t.Errorf("%s: required %q is not among its properties", at, name)
					}
				}
			}
		}
	}
	walk("#", s.root)
}
