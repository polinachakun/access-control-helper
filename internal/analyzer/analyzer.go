// Package analyzer integrates with the Alloy model checker to formally verify
// the generated .als specification. It invokes the Alloy jar via the Java CLI
// and parses the check-result output.
//
// The Alloy jar is expected at tools/org.alloytools.alloy.dist.jar relative to
// the running binary.
package analyzer

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type CheckResult struct {
	// Name is the assertion name passed to the check command.
	Name string
	// Valid is true when Alloy found no counterexample (assertion holds).
	Valid bool
	// HasCounterExample is true when Alloy found a counterexample.
	HasCounterExample bool
	// RawOutput is the raw Alloy output lines for this check.
	RawOutput string
}

// Analyzer runs Alloy checks on a generated .als file.
type Analyzer struct {
	javaPath string
	jarPath  string
}

// New creates an Analyzer using the bundled Alloy jar and the system java executable.
func New() *Analyzer {
	return &Analyzer{
		javaPath: findJava(),
		jarPath:  bundledJarPath(),
	}
}

// bundledJarPath returns the path to the Alloy jar bundled in tools/.
// It checks next to the binary first, then relative to the working directory
// (the latter covers `go run` and development workflows).
func bundledJarPath() string {
	const rel = "tools/org.alloytools.alloy.dist.jar"

	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), rel)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	if cwd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(cwd, rel)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	return ""
}

// NewWithPaths creates an Analyzer with explicit paths.
func NewWithPaths(javaPath, jarPath string) *Analyzer {
	return &Analyzer{javaPath: javaPath, jarPath: jarPath}
}

// Available returns true when both java and the Alloy jar have been located.
func (a *Analyzer) Available() bool {
	return a.javaPath != "" && a.jarPath != ""
}

// JarPath returns the resolved jar path (empty string if not found).
func (a *Analyzer) JarPath() string { return a.jarPath }

// Check runs all `check` commands in specFile and returns one CheckResult per command.
// Returns an error only when the Alloy process cannot be started.
func (a *Analyzer) Check(specFile string) ([]CheckResult, error) {
	if !a.Available() {
		return nil, fmt.Errorf("alloy not available")
	}

	output, err := runAlloy(a.javaPath, a.jarPath, specFile)

	// Clean up the output directory Alloy creates (e.g. "output4.als" → "output4/").
	defer cleanupAlloyOutput(specFile)

	if err != nil {
		return nil, fmt.Errorf("alloy execution failed: %w\nraw output:\n%s", err, output)
	}

	results := parseOutput(output)
	if len(results) == 0 {
		return nil, fmt.Errorf("no Alloy check results were parsed\nraw output:\n%s", output)
	}

	return results, nil
}

// cleanupAlloyOutput removes the directory Alloy creates next to the spec file.
func cleanupAlloyOutput(specFile string) {
	base := strings.TrimSuffix(filepath.Base(specFile), filepath.Ext(specFile))
	dir := filepath.Join(filepath.Dir(specFile), base)
	os.RemoveAll(dir)
}

// ── Output parsing ────────────────────────────────────────────────────────────

var checkLineRe = regexp.MustCompile(`^\d+\.\s+check\s+(\w+)\s+.*\b(SAT|UNSAT)\s*$`)

func parseOutput(raw string) []CheckResult {
	var results []CheckResult

	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := sc.Text()
		m := checkLineRe.FindStringSubmatch(line)
		if len(m) < 3 {
			continue
		}
		r := CheckResult{Name: m[1], RawOutput: line + "\n"}
		if m[2] == "UNSAT" {
			r.Valid = true
		} else {
			r.HasCounterExample = true
		}
		results = append(results, r)
	}

	return results
}

// ── Alloy invocation ──────────────────────────────────────────────────────────

func runAlloy(javaPath, jarPath, specFile string) (string, error) {
	// -f overwrites the output directory if it already exists from a prior run.
	cmd := exec.Command(javaPath, "-jar", jarPath, "exec", "-f", specFile)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ── Java discovery ────────────────────────────────────────────────────────────

func findJava() string {
	if home := os.Getenv("JAVA_HOME"); home != "" {
		candidate := filepath.Join(home, "bin", "java")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if path, err := exec.LookPath("java"); err == nil {
		return path
	}
	return ""
}
