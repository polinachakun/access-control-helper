// Package analyzer integrates with the Alloy model checker to formally verify
// the generated .als specification. It discovers the Alloy jar, invokes it via
// the Java CLI, and parses the check-result output.
//
// The Alloy jar path is resolved in this order:
//  1. ALLOY_JAR environment variable
//  2. Common file-system locations (./alloy.jar, ~/alloy.jar, /usr/local/lib/alloy.jar)
//  3. "alloy.jar" on PATH
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

// CheckResult holds the outcome of a single Alloy `check` command.
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

// New creates an Analyzer, resolving the Alloy jar and java executable.
func New() *Analyzer {
	return &Analyzer{
		javaPath: findJava(),
		jarPath:  findAlloyJar(),
	}
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
		return nil, fmt.Errorf("Alloy not available (set ALLOY_JAR env var to the path of alloy.jar)")
	}

	// Alloy 4.x: java -cp alloy.jar edu.mit.csail.sdg.alloy4whole.ExampleUsingTheAPI <file>
	// Alloy 6.x / alloy-run: java -jar alloy.jar <file>
	// We try both invocations; the second (simpler) is tried first.
	output, err := runAlloy(a.javaPath, a.jarPath, specFile)
	if err != nil && len(output) == 0 {
		return nil, fmt.Errorf("alloy execution failed: %w", err)
	}

	return parseOutput(output), nil
}

// ── Output parsing ────────────────────────────────────────────────────────────

var (
	// "   Executing "Check <Name> for ..."
	executingRe = regexp.MustCompile(`Executing\s+"Check\s+(\w+)`)
	// "   No counterexample found."
	noCounterRe = regexp.MustCompile(`No counterexample found`)
	// "   Counterexample found."
	counterRe = regexp.MustCompile(`Counterexample found`)
)

func parseOutput(raw string) []CheckResult {
	var results []CheckResult
	var cur *CheckResult

	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := sc.Text()

		if m := executingRe.FindStringSubmatch(line); len(m) > 1 {
			if cur != nil {
				results = append(results, *cur)
			}
			cur = &CheckResult{Name: m[1]}
		}

		if cur != nil {
			cur.RawOutput += line + "\n"
			if noCounterRe.MatchString(line) {
				cur.Valid = true
			}
			if counterRe.MatchString(line) {
				cur.HasCounterExample = true
			}
		}
	}

	if cur != nil {
		results = append(results, *cur)
	}
	return results
}

// ── Alloy invocation ──────────────────────────────────────────────────────────

func runAlloy(javaPath, jarPath, specFile string) (string, error) {
	// Try simple -jar invocation first (works with alloy-run and Alloy 6).
	cmd := exec.Command(javaPath, "-jar", jarPath, specFile)
	out, err := cmd.CombinedOutput()
	if err == nil || len(out) > 0 {
		return string(out), err
	}

	// Fallback: Alloy 4 API class.
	cmd = exec.Command(javaPath,
		"-cp", jarPath,
		"edu.mit.csail.sdg.alloy4whole.ExampleUsingTheAPI",
		specFile,
	)
	out, err = cmd.CombinedOutput()
	return string(out), err
}

// ── Discovery helpers ─────────────────────────────────────────────────────────

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

func findAlloyJar() string {
	// 1. Explicit env var
	if j := os.Getenv("ALLOY_JAR"); j != "" {
		return j
	}

	// 2. Common locations
	home, _ := os.UserHomeDir()
	candidates := []string{
		"alloy.jar",
		"alloy4.2.jar",
		filepath.Join(".", "alloy.jar"),
		filepath.Join(home, "alloy.jar"),
		filepath.Join(home, "bin", "alloy.jar"),
		"/usr/local/lib/alloy.jar",
		"/usr/local/bin/alloy.jar",
		"/opt/alloy/alloy.jar",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	// 3. On PATH
	if path, err := exec.LookPath("alloy.jar"); err == nil {
		return path
	}
	return ""
}
