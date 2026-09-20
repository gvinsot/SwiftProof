// Package coverage resolves changed lines against a recorded Go coverage
// profile. Executed means a line ran at least once during the recorded run; it
// is never a claim that behavior is asserted, correct or safe. Absent,
// truncated, unparsable or unmapped data always resolves to "not measured" and
// never to a not-executed claim.
package coverage

import (
	"bytes"
	"errors"
	"strconv"
)

// ProfilePath is the fixed in-container path a coverage command must write to.
// /tmp is a fresh tmpfs per run and the snapshot is copied to /workspace, so a
// committed or stale profile cannot occupy it and no discovery is needed.
const ProfilePath = "/tmp/swiftproof-coverage.out"

const (
	// CommandKey names the optional trusted policy command.
	CommandKey = "coverage"
	// Placeholder must appear exactly once in that command's argv.
	Placeholder = "{coverage_out}"
)

// FrameHeader precedes the decimal payload length and a newline; FrameFooter
// must match exactly at the declared offset. The sandbox wrapper that emits the
// frame is built from these constants so producer and decoder cannot drift.
const (
	FrameHeader = "SWIFTPROOF-COVERAGE-BEGIN "
	FrameFooter = "SWIFTPROOF-COVERAGE-END\n"
)

// Every error message is the exact sentence reported to the user, so a caller
// records err.Error() as the reason a measurement did not happen.
var (
	ErrNoProfile  = errors.New("no coverage profile was emitted by the coverage command")
	ErrTruncated  = errors.New("the coverage profile did not fit in the sandbox payload budget or was cut short; raise sandbox.max_output_bytes")
	ErrPolluted   = errors.New("the coverage payload channel carried unexpected output")
	ErrNotGo      = errors.New("the coverage profile is not a Go coverage profile; only Go coverage profiles are supported in this version")
	ErrBlockLimit = errors.New("the coverage profile exceeded the parser bound of 200000 blocks")
	ErrModulePath = errors.New("the module path could not be read from go.mod in the candidate snapshot")
	ErrArtifact   = errors.New("the coverage profile could not be retained as evidence")
)

// DecodeFrame returns the profile bytes of the single length-declared frame on
// the payload channel. The declared length is verified by exact arithmetic and
// never by searching for the terminator: a payload cut short must fail loudly,
// because a silently shortened profile parses as "these lines never ran".
func DecodeFrame(payload []byte, truncated bool) ([]byte, error) {
	if truncated {
		return nil, ErrTruncated
	}
	start := bytes.Index(payload, []byte(FrameHeader))
	if start < 0 {
		return nil, ErrNoProfile
	}
	if len(bytes.TrimSpace(payload[:start])) != 0 {
		return nil, ErrPolluted
	}
	rest := payload[start+len(FrameHeader):]
	newline := bytes.IndexByte(rest, '\n')
	if newline < 0 {
		return nil, ErrTruncated
	}
	declared, err := strconv.Atoi(string(rest[:newline]))
	if err != nil || declared < 1 {
		return nil, ErrPolluted
	}
	body := rest[newline+1:]
	if len(body) != declared+len(FrameFooter) || !bytes.Equal(body[declared:], []byte(FrameFooter)) {
		return nil, ErrTruncated
	}
	profile := body[:declared]
	// A second header inside the declared payload means something other than the
	// wrapper wrote to the channel; refuse rather than pick a winner.
	if bytes.Contains(profile, []byte(FrameHeader)) {
		return nil, ErrPolluted
	}
	return profile, nil
}
