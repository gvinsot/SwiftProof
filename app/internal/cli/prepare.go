package cli

// F0 stub of the trusted dependency-preparation stage (F8 owns this file). A
// configured prepare policy fails closed: no image is produced, no repository
// code runs, and the run exits 4.

import (
	"context"
	"io"

	"github.com/gvinsot/SwiftProof/app/internal/config"
	"github.com/gvinsot/SwiftProof/app/internal/gitrepo"
	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// preparation is the outcome of the prepare stage.
type preparation struct {
	image      string           // the derived image ID to run checks in; "" unless ok
	record     *model.Prepare   // the report's prepare object
	artifacts  []model.Artifact // prepare_output
	audit      []model.AuditEvent
	unverified []string
	ok         bool
}

// prepareSignals returns the prepare_input_changed signals of a change that
// edits a declared prepare input (lint and review). The stub returns none.
func prepareSignals(spec *config.Prepare, change model.Change) []model.Signal { return nil }

// runPrepare derives the sandbox image from inputs exported from the base
// commit. It never falls back to the unprepared image. The stub fails closed.
func runPrepare(ctx context.Context, repo *gitrepo.Repository, cfg config.Config, change model.Change, artifactDir string, allowNetwork bool, version string, errOut io.Writer) preparation {
	record := prepareRecord(cfg, change, model.PrepareFailed, "dependency preparation is not implemented in this build")
	record.Network = allowNetwork
	return preparation{
		record:     record,
		unverified: []string{"Dependency preparation failed: not implemented in this build. No repository code was executed."},
	}
}

// prepareNotRun is the prepare object of a review that needed no execution.
func prepareNotRun(cfg config.Config, change model.Change, reason string) *model.Prepare {
	return prepareRecord(cfg, change, model.PrepareNotRun, reason)
}

// prepareRecord builds a prepare object for a stage that produced no image.
// Network stays false unless the caller records the effective setting.
func prepareRecord(cfg config.Config, change model.Change, status, reason string) *model.Prepare {
	p := &model.Prepare{
		Status: status, Reason: reason, SourceCommit: change.BaseCommit, Command: []string{},
		User: cfg.Prepare.EffectiveUser(), BaseImage: cfg.Sandbox.Image, Inputs: []model.PreparedInput{}, Note: model.PrepareNote,
	}
	if cfg.Prepare != nil {
		p.Command = append(p.Command, cfg.Prepare.Command...)
	}
	return p
}
