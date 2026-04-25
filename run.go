package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"access-control-helper/internal/analyzer"
	"access-control-helper/internal/generator"
	"access-control-helper/internal/ir"
	"access-control-helper/internal/parser"
	"access-control-helper/internal/preflight"
	"access-control-helper/internal/reporter"
	"access-control-helper/internal/resolver"
)

// runToStdout parses inputPath and writes only the generated Alloy spec to
// stdout (no Alloy verification). Used when no output path is provided.
func runToStdout(inputPath string) error {
	p := parser.NewParser()

	fi, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}

	var parseResult *parser.ParseResult
	if fi.IsDir() {
		parseResult, err = p.ParseDirectory(inputPath)
	} else {
		parseResult, err = p.ParseFile(inputPath)
	}
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	res := resolver.NewResolver()
	resources, err := res.Resolve(parseResult)
	if err != nil {
		return fmt.Errorf("resolve: %w", err)
	}

	config, warnings, err := ir.BuildFromResources(resources, res.GetGraph())
	if err != nil {
		return fmt.Errorf("IR build: %w", err)
	}
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	sourceFile := filepath.Base(inputPath)
	gen := generator.NewGenerator(config, sourceFile)
	return gen.GenerateToWriter(os.Stdout)
}

// run executes the full pipeline for inputPath, writes the Alloy spec to
// outputPath, runs Alloy verification, and writes the report to out.
func run(inputPath, outputPath string, out io.Writer) error {
	// ── Step 0: Terraform HCL syntax pre-check ────────────────────────────
	if r := preflight.CheckTerraform(inputPath, os.Stderr); !r.Passed {
		return fmt.Errorf("Terraform HCL syntax check failed — fix formatting before analysis:\n%s\n"+
			"  Run: terraform fmt %s", r.Output, inputPath)
	}

	// ── Step 1: Parse ─────────────────────────────────────────────────────
	p := parser.NewParser()

	fi, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}

	var parseResult *parser.ParseResult
	if fi.IsDir() {
		parseResult, err = p.ParseDirectory(inputPath)
	} else {
		parseResult, err = p.ParseFile(inputPath)
	}
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	// ── Step 2: Resolve cross-references ─────────────────────────────────
	res := resolver.NewResolver()
	resources, err := res.Resolve(parseResult)
	if err != nil {
		return fmt.Errorf("resolve: %w", err)
	}

	// ── Step 3: Build intermediate representation ─────────────────────────
	config, warnings, err := ir.BuildFromResources(resources, res.GetGraph())
	if err != nil {
		return fmt.Errorf("IR build: %w", err)
	}
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	// Fail fast before invoking Alloy if the config is structurally invalid.
	for _, ve := range config.Validate() {
		if ve.Fatal {
			return fmt.Errorf("configuration error: %s", ve.Message)
		}
		fmt.Fprintf(os.Stderr, "warning: %s\n", ve.Message)
	}

	fmt.Fprintf(os.Stderr, "IR: %d bucket(s), %d role(s), %d bucket policy(ies), %d RCP(s), %d SCP(s)\n",
		len(config.Buckets), len(config.Roles), len(config.BucketPolicies),
		len(config.RCPs()), len(config.SCPs()))

	// ── Step 4: Generate Alloy specification ─────────────────────────────
	sourceFile := filepath.Base(inputPath)
	gen := generator.NewGenerator(config, sourceFile)

	if err := gen.GenerateToFile(outputPath); err != nil {
		return fmt.Errorf("generate: %w", err)
	}

	tripleKeys := gen.TripleMetadata()
	if len(tripleKeys) == 0 {
		return fmt.Errorf("no (principal, bucket, action) triples to analyse — " +
			"check that the input contains both IAM roles with S3 actions and S3 buckets")
	}

	// ── Step 5: Alloy formal verification ────────────────────────────────
	alloyAnalyzer := analyzer.New()
	if !alloyAnalyzer.Available() {
		return fmt.Errorf("Alloy jar not found at tools/org.alloytools.alloy.dist.jar")
	}

	fmt.Fprintln(os.Stderr, "Running Alloy formal verification…")
	checkResults, err := alloyAnalyzer.Check(outputPath)
	if err != nil {
		return fmt.Errorf("Alloy: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Alloy completed %d check(s).\n", len(checkResults))

	// ── Step 6: Consistency check ─────────────────────────────────────────
	expectedChecks := len(tripleKeys) * 8
	if len(checkResults) != expectedChecks {
		return fmt.Errorf(
			"Alloy returned %d check result(s), expected %d (8 per triple × %d triple(s)); pipeline is inconsistent",
			len(checkResults), expectedChecks, len(tripleKeys),
		)
	}

	// ── Step 7: Report ────────────────────────────────────────────────────
	tripleResults, err := reporter.BuildTripleResults(checkResults, tripleKeys)
	if err != nil {
		return fmt.Errorf("report: %w", err)
	}
	rep := reporter.New(out)
	rep.Summary(tripleResults)
	rep.Report(tripleResults)

	return nil
}
