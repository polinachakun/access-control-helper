package main

import (
	"fmt"
	"os"
	"path/filepath"

	"access-control-helper/internal/analyzer"
	"access-control-helper/internal/generator"
	"access-control-helper/internal/ir"
	"access-control-helper/internal/parser"
	"access-control-helper/internal/reporter"
	"access-control-helper/internal/resolver"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	inputPath := os.Args[1]
	toStdout := len(os.Args) < 3 || os.Args[2] == "-"
	outputPath := ""
	if !toStdout {
		outputPath = os.Args[2]
	}

	// ── Step 1: Parse ─────────────────────────────────────────────────────
	p := parser.NewParser()

	fi, err := os.Stat(inputPath)
	if err != nil {
		fatalf("error: %v\n", err)
	}

	var parseResult *parser.ParseResult
	if fi.IsDir() {
		parseResult, err = p.ParseDirectory(inputPath)
	} else {
		parseResult, err = p.ParseFile(inputPath)
	}
	if err != nil {
		fatalf("parse error: %v\n", err)
	}

	// ── Step 2: Resolve cross-references ─────────────────────────────────
	res := resolver.NewResolver()
	resources, err := res.Resolve(parseResult)
	if err != nil {
		fatalf("resolve error: %v\n", err)
	}

	// ── Step 3: Build intermediate representation ─────────────────────────
	config, err := ir.BuildFromResources(resources, res.GetGraph())
	if err != nil {
		fatalf("IR build error: %v\n", err)
	}

	logf("IR: %d bucket(s), %d role(s), %d bucket policy(ies), %d RCP(s), %d SCP(s)\n",
		len(config.Buckets), len(config.Roles), len(config.BucketPolicies),
		len(config.RCPs()), len(config.SCPs()))

	// ── Step 4: Generate Alloy specification ─────────────────────────────
	sourceFile := filepath.Base(inputPath)
	gen := generator.NewGenerator(config, sourceFile)

	if toStdout {
		// Stdout mode: only emit the Alloy spec so it can be piped or redirected.
		if err := gen.GenerateToWriter(os.Stdout); err != nil {
			fatalf("generate error: %v\n", err)
		}
		return
	}

	if err := gen.GenerateToFile(outputPath); err != nil {
		fatalf("generate error: %v\n", err)
	}
	logf("Generated Alloy spec: %s\n", outputPath)

	tripleKeys := gen.TripleMetadata()

	// ── Step 5: Alloy formal verification ────────────────────────────────
	alloyAnalyzer := analyzer.New()
	if !alloyAnalyzer.Available() {
		fatalf("error: Alloy jar not found.\n" +
			"Expected at: tools/org.alloytools.alloy.dist.jar\n" +
			"Alloy is required for access evaluation.\n")
	}

	logf("Running Alloy formal verification…\n")
	checkResults, err := alloyAnalyzer.Check(outputPath)
	if err != nil {
		fatalf("Alloy failed: %v\n", err)
	}
	logf("Alloy completed %d check(s).\n", len(checkResults))

	// ── Step 6: Report ────────────────────────────────────────────────────
	tripleResults := reporter.BuildTripleResults(checkResults, tripleKeys)
	rep := reporter.New(os.Stdout)
	rep.Summary(tripleResults)
	rep.Report(tripleResults)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func logf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}

func printUsage() {
	prog := os.Args[0]
	fmt.Fprintln(os.Stderr, "AWS S3 Access Control Helper — Alloy-based formal policy analysis")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  %s <tf-file-or-dir>                  Print Alloy spec to stdout\n", prog)
	fmt.Fprintf(os.Stderr, "  %s <tf-file-or-dir> <output.als>     Write spec + run Alloy analysis\n", prog)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Environment variables:")
	fmt.Fprintln(os.Stderr, "  JAVA_HOME   Java installation root")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Examples:")
	fmt.Fprintf(os.Stderr, "  %s testdata/scenario2.tf                # Alloy spec to stdout\n", prog)
	fmt.Fprintf(os.Stderr, "  %s testdata/scenario2.tf output.als     # write spec + run Alloy analysis\n", prog)
}
