package main

import (
	"fmt"
	"os"
	"path/filepath"

	"access-control-helper/internal/generator"
	"access-control-helper/internal/ir"
	"access-control-helper/internal/parser"
	"access-control-helper/internal/resolver"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	inputPath := os.Args[1]
	outputPath := ""
	toStdout := len(os.Args) < 3 || os.Args[2] == "-"
	if !toStdout {
		outputPath = os.Args[2]
	}

	// Step 1: Parse — accept a single .tf file or a directory
	p := parser.NewParser()

	fi, err := os.Stat(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var parseResult *parser.ParseResult
	if fi.IsDir() {
		parseResult, err = p.ParseDirectory(inputPath)
	} else {
		parseResult, err = p.ParseFile(inputPath)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse error: %v\n", err)
		os.Exit(1)
	}

	if !toStdout {
		fmt.Fprintf(os.Stderr, "Parsed %d resources from %s\n", len(parseResult.Resources), inputPath)
	}

	// Step 2: Resolve cross-references between resources
	res := resolver.NewResolver()
	resources, err := res.Resolve(parseResult)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve error: %v\n", err)
		os.Exit(1)
	}

	// Step 3: Build intermediate representation
	config, err := ir.BuildFromResources(resources, res.GetGraph())
	if err != nil {
		fmt.Fprintf(os.Stderr, "IR build error: %v\n", err)
		os.Exit(1)
	}

	if !toStdout {
		fmt.Fprintf(os.Stderr, "IR: %d bucket(s), %d role(s), %d bucket policy(ies)\n",
			len(config.Buckets), len(config.Roles), len(config.BucketPolicies))
	}

	// Step 4: Generate Alloy specification
	sourceFile := filepath.Base(inputPath)

	if toStdout {
		if err := generator.GenerateToWriter(config, sourceFile, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "generate error: %v\n", err)
			os.Exit(1)
		}
	} else {
		if err := generator.Generate(config, sourceFile, outputPath); err != nil {
			fmt.Fprintf(os.Stderr, "generate error: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Generated Alloy spec: %s\n", outputPath)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <terraform-file-or-dir> [output-als-file]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  <terraform-file-or-dir>  path to a .tf file or a directory of .tf files\n")
	fmt.Fprintf(os.Stderr, "  [output-als-file]        write Alloy spec to this file (omit to print to stdout)\n")
	fmt.Fprintf(os.Stderr, "                           use - to explicitly print to stdout\n")
	fmt.Fprintf(os.Stderr, "\nExamples:\n")
	fmt.Fprintf(os.Stderr, "  %s testdata/scenario1.tf              # print Alloy spec to stdout\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s testdata/scenario1.tf output.als   # write to file\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s testdata/                          # all .tf files in dir → stdout\n", os.Args[0])
}
