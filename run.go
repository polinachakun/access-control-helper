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

	config, err := ir.BuildFromResources(resources, res.GetGraph())
	if err != nil {
		return fmt.Errorf("IR build: %w", err)
	}

	sourceFile := filepath.Base(inputPath)
	gen := generator.NewGenerator(config, sourceFile)
	return gen.GenerateToWriter(os.Stdout)
}

// run executes the full pipeline for inputPath, writes the Alloy spec to
// outputPath, runs Alloy verification, and writes the report to out.
func run(inputPath, outputPath string, out io.Writer) error {
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
	config, err := ir.BuildFromResources(resources, res.GetGraph())
	if err != nil {
		return fmt.Errorf("IR build: %w", err)
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

	// ── Step 6: Report ────────────────────────────────────────────────────
	tripleResults := reporter.BuildTripleResults(checkResults, tripleKeys)
	rep := reporter.New(out)
	rep.Summary(tripleResults)
	rep.Report(tripleResults)

	return nil
}
