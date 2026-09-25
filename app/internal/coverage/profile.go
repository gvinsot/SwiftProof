package coverage

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	maxProfileBytes = 8 << 20
	maxBlocks       = 200000
)

// Block is one instrumented range of a Go coverage profile. Count is the number
// of times the block ran during the recorded run.
type Block struct {
	File      string
	StartLine int
	EndLine   int
	NumStmts  int
	Count     int
}

// Profile is a parsed Go coverage profile. It holds only what the profile
// itself stated; nothing is inferred from the filesystem or from the diff.
type Profile struct {
	Mode   string
	Blocks []Block
}

// ParseGoProfile parses `mode: set|count|atomic` followed by
// `path:startLine.startCol,endLine.endCol numStmts count` rows.
//
// A malformed row fails the whole profile and no row is ever skipped: a skipped
// row silently removes lines from the instrumented set, which renders
// downstream as "no executable code here" or, worse, as "not executed".
func ParseGoProfile(b []byte) (*Profile, error) {
	if len(b) > maxProfileBytes {
		return nil, ErrBlockLimit
	}
	profile := &Profile{}
	index := map[string]int{}
	for row, raw := range strings.Split(string(b), "\n") {
		text := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(text) == "" {
			continue
		}
		if profile.Mode == "" {
			mode, ok := strings.CutPrefix(text, "mode: ")
			if !ok || mode != "set" && mode != "count" && mode != "atomic" {
				return nil, ErrNotGo
			}
			profile.Mode = mode
			continue
		}
		block, err := parseBlock(text)
		if err != nil {
			return nil, fmt.Errorf("the coverage profile could not be parsed at line %d", row+1)
		}
		key := fmt.Sprintf("%s:%d.%d", block.File, block.StartLine, block.EndLine)
		if at, seen := index[key]; seen {
			// The cover tool can emit the same range more than once; summing is
			// the only resolution that cannot turn an executed block into an
			// unexecuted one.
			profile.Blocks[at].Count += block.Count
			continue
		}
		if len(profile.Blocks) >= maxBlocks {
			return nil, ErrBlockLimit
		}
		index[key] = len(profile.Blocks)
		profile.Blocks = append(profile.Blocks, block)
	}
	if profile.Mode == "" {
		return nil, ErrNotGo
	}
	sort.Slice(profile.Blocks, func(i, j int) bool {
		a, b := profile.Blocks[i], profile.Blocks[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.StartLine != b.StartLine {
			return a.StartLine < b.StartLine
		}
		return a.EndLine < b.EndLine
	})
	return profile, nil
}

func parseBlock(text string) (Block, error) {
	fields := strings.Fields(text)
	if len(fields) != 3 {
		return Block{}, errSyntax
	}
	// Go import paths may contain a colon, so the position separator is the last one.
	colon := strings.LastIndex(fields[0], ":")
	if colon <= 0 || colon == len(fields[0])-1 {
		return Block{}, errSyntax
	}
	file, span := fields[0][:colon], fields[0][colon+1:]
	from, to, ok := strings.Cut(span, ",")
	if !ok {
		return Block{}, errSyntax
	}
	startLine, _, err := position(from)
	if err != nil {
		return Block{}, err
	}
	endLine, _, err := position(to)
	if err != nil {
		return Block{}, err
	}
	numStmts, err := count(fields[1])
	if err != nil {
		return Block{}, err
	}
	executions, err := count(fields[2])
	if err != nil {
		return Block{}, err
	}
	if startLine < 1 || endLine < startLine {
		return Block{}, errSyntax
	}
	return Block{File: file, StartLine: startLine, EndLine: endLine, NumStmts: numStmts, Count: executions}, nil
}

func position(s string) (int, int, error) {
	lineText, columnText, ok := strings.Cut(s, ".")
	if !ok {
		return 0, 0, errSyntax
	}
	line, err := count(lineText)
	if err != nil {
		return 0, 0, err
	}
	column, err := count(columnText)
	if err != nil {
		return 0, 0, err
	}
	return line, column, nil
}

func count(s string) (int, error) {
	value, err := strconv.Atoi(s)
	if err != nil || value < 0 {
		return 0, errSyntax
	}
	return value, nil
}

type syntaxError struct{}

func (syntaxError) Error() string { return "malformed coverage profile row" }

var errSyntax = syntaxError{}
