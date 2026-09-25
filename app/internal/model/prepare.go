package model

// Dependency-preparation statuses.
const (
	PrepareBuilt        = "built"
	PrepareReused       = "reused"
	PrepareFailed       = "failed"
	PrepareNotPermitted = "not_permitted"
	PrepareNotRun       = "not_run"
)

// PrepareNote is the fixed note of the prepare section. F8 owns its final text;
// this neutral sentence makes no claim.
const PrepareNote = "See the documentation for what this section does and does not establish."

type PreparedInput struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Prepare is the dependency-preparation section. It is present exactly when
// the policy has prepare in review mode.
type Prepare struct {
	Status       string          `json:"status"`
	Reason       string          `json:"reason,omitempty"`
	SourceCommit string          `json:"source_commit"` // change.BaseCommit
	Command      []string        `json:"command"`
	User         string          `json:"user"`    // sandbox | root
	Network      bool            `json:"network"` // effective
	Key          string          `json:"key,omitempty"`
	BaseImage    string          `json:"base_image"`
	BaseImageID  string          `json:"base_image_id,omitempty"`
	ImageID      string          `json:"image_id,omitempty"`
	AddedBytes   int64           `json:"added_bytes,omitempty"`
	Inputs       []PreparedInput `json:"inputs"`
	LogSHA256    string          `json:"log_sha256,omitempty"`
	DurationMS   int64           `json:"duration_ms"`
	Note         string          `json:"note"`
}
