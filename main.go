package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	inputPath := os.Args[1]

	if len(os.Args) >= 3 && os.Args[2] == "-" {
		if err := runToStdout(inputPath); err != nil {
			fatalf("error: %v\n", err)
		}
		return
	}

	var outputPath string
	if len(os.Args) >= 3 {
		outputPath = os.Args[2]
	} else {
		// Auto-derive output path: <binary-dir>/output/<inputbasename>.als
		// Using the binary's directory (not CWD) avoids polluting whatever
		// directory the caller happens to be in.
		exe, err := os.Executable()
		if err != nil {
			fatalf("error resolving binary path: %v\n", err)
		}
		outDir := filepath.Join(filepath.Dir(exe), "output")
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			fatalf("error creating output dir: %v\n", err)
		}
		base := filepath.Base(filepath.Clean(inputPath))
		base = strings.TrimSuffix(base, filepath.Ext(base))
		outputPath = filepath.Join(outDir, base+".als")
	}

	if err := run(inputPath, outputPath, os.Stdout); err != nil {
		fatalf("error: %v\n", err)
	}
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
	fmt.Fprintf(os.Stderr, "  %s <tf-file-or-dir>                  Write spec to output/ + run Alloy analysis\n", prog)
	fmt.Fprintf(os.Stderr, "  %s <tf-file-or-dir> -                Print Alloy spec to stdout only\n", prog)
	fmt.Fprintf(os.Stderr, "  %s <tf-file-or-dir> <output.als>     Write spec + run Alloy analysis\n", prog)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Environment variables:")
	fmt.Fprintln(os.Stderr, "  JAVA_HOME   Java installation root")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Examples:")
	fmt.Fprintf(os.Stderr, "  %s testdata/scenario2.tf                # write to output/scenario2.als + run Alloy\n", prog)
	fmt.Fprintf(os.Stderr, "  %s testdata/scenario2.tf -              # Alloy spec to stdout\n", prog)
	fmt.Fprintf(os.Stderr, "  %s testdata/scenario2.tf output.als     # write spec + run Alloy analysis\n", prog)
}
