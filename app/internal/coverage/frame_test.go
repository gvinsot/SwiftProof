package coverage

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func frame(body string) []byte {
	return []byte(fmt.Sprintf("%s%d\n%s%s", FrameHeader, len(body), body, FrameFooter))
}

func TestDecodeFrameAcceptsValidFrame(t *testing.T) {
	body := "mode: count\nexample.com/m/a.go:1.1,2.2 1 3\n"
	got, err := DecodeFrame(frame(body), false)
	if err != nil {
		t.Fatalf("valid frame rejected: %v", err)
	}
	if string(got) != body {
		t.Fatalf("payload altered: %q", got)
	}
}

// A payload cut short must fail rather than parse as a shorter profile: a
// shorter profile reads as "these lines never ran".
func TestDecodeFrameRejectsShortPayload(t *testing.T) {
	body := strings.Repeat("x", 120)
	payload := []byte(fmt.Sprintf("%s400\n%s%s", FrameHeader, body, FrameFooter))
	if _, err := DecodeFrame(payload, false); !errors.Is(err, ErrTruncated) {
		t.Fatalf("a profile declared at 400 bytes and delivered at 120 was accepted: %v", err)
	}
}

func TestDecodeFrameRejectsTruncatedFlag(t *testing.T) {
	if _, err := DecodeFrame(frame("mode: set\n"), true); !errors.Is(err, ErrTruncated) {
		t.Fatalf("a writer that reported truncation was trusted: %v", err)
	}
}

func TestDecodeFrameRejectsMissingTerminator(t *testing.T) {
	body := "mode: set\n"
	payload := []byte(fmt.Sprintf("%s%d\n%s", FrameHeader, len(body), body))
	if _, err := DecodeFrame(payload, false); !errors.Is(err, ErrTruncated) {
		t.Fatalf("missing terminator accepted: %v", err)
	}
}

// The declared length decides where the profile ends, so a terminator appearing
// inside the profile cannot shorten the frame.
func TestDecodeFrameRejectsNestedSentinel(t *testing.T) {
	body := "mode: count\n" + FrameFooter + "example.com/m/a.go:1.1,2.2 1 0\n"
	got, err := DecodeFrame(frame(body), false)
	if err != nil {
		t.Fatalf("frame whose profile embeds the terminator was rejected: %v", err)
	}
	if string(got) != body {
		t.Fatalf("frame truncated at the embedded terminator: %q", got)
	}
}

func TestDecodeFrameRejectsSecondHeader(t *testing.T) {
	body := "mode: set\n" + FrameHeader + "9\n"
	if _, err := DecodeFrame(frame(body), false); !errors.Is(err, ErrPolluted) {
		t.Fatalf("a second frame header inside the payload was accepted: %v", err)
	}
}

func TestDecodeFrameRejectsBytesBeforeHeader(t *testing.T) {
	payload := append([]byte("PASS ok\n"), frame("mode: set\n")...)
	if _, err := DecodeFrame(payload, false); !errors.Is(err, ErrPolluted) {
		t.Fatalf("output written directly to the payload channel was accepted: %v", err)
	}
	// Trailing newlines from the wrapper itself remain acceptable.
	if _, err := DecodeFrame(append([]byte("\n \n"), frame("mode: set\n")...), false); err != nil {
		t.Fatalf("whitespace before the header rejected: %v", err)
	}
}

func TestDecodeFrameRejectsNonNumericLength(t *testing.T) {
	for _, length := range []string{"abc", "-4", "0", ""} {
		payload := []byte(FrameHeader + length + "\nmode: set\n" + FrameFooter)
		if _, err := DecodeFrame(payload, false); err == nil {
			t.Fatalf("declared length %q accepted", length)
		}
	}
}

func TestDecodeFrameRejectsEmptyPayload(t *testing.T) {
	if _, err := DecodeFrame(nil, false); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("empty payload: %v", err)
	}
	if _, err := DecodeFrame([]byte("ok  github.com/x  0.1s\n"), false); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("log-only payload: %v", err)
	}
}
