// Package analyzer runs Alloy checks on generated .als files.
// The Alloy jar is expected at tools/org.alloytools.alloy.dist.jar.
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
	Name              string
	Valid             bool // true = no counterexample (assertion holds)
	HasCounterExample bool
	RawOutput         string
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
func (a *Analyzer) Check(specFile string) ([]CheckResult, error) {
	if !a.Available() {
		return nil, fmt.Errorf("alloy not available")
	}

	output, err := runAlloy(a.javaPath, a.jarPath, specFile)

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

func cleanupAlloyOutput(specFile string) {
	base := strings.TrimSuffix(filepath.Base(specFile), filepath.Ext(specFile))
	dir := filepath.Join(filepath.Dir(specFile), base)
	os.RemoveAll(dir)
}

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

func runAlloy(javaPath, jarPath, specFile string) (string, error) {
	cmd := exec.Command(javaPath, "-jar", jarPath, "exec", "-f", specFile)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

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
