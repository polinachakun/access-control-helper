// Package e2e_test implements end-to-end scenario tests for the access-control-helper
// pipeline. Tests are auto-discovered from the scenarios/ subdirectory.
//
// Usage:
//
//	go test ./tests/              – run all tests (skip Alloy step if JAR absent)
//	go test ./tests/ -update      – regenerate expect.json from current Alloy output
package e2e_test

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"

	"access-control-helper/internal/analyzer"
	"access-control-helper/internal/generator"
	"access-control-helper/internal/ir"
	"access-control-helper/internal/parser"
	"access-control-helper/internal/reporter"
	"access-control-helper/internal/resolver"
)

var update = flag.Bool("update", false, "write expect.json from current Alloy output")

// ── ExpectFile mirrors the expect.json schema ─────────────────────────────────

type ExpectFile struct {
	SchemaVersion int           `json:"schema_version"`
	Name          string        `json:"name"`
	Queries       []ExpectQuery `json:"queries"`
}

type ExpectQuery struct {
	Principal string            `json:"principal"`
	Bucket    string            `json:"bucket"`
	Action    string            `json:"action"`
	Decision  string            `json:"decision"`
	DeniedAt  *string           `json:"denied_at"`
	Layers    map[string]string `json:"layers"`
}

// ── TestScenarios_Generation: always runs, no Alloy needed ───────────────────

// TestScenarios_Generation verifies that every scenario folder can be parsed,
// resolved, and compiled into an Alloy specification without errors.
// This test does NOT require the Alloy JAR and always runs.
func TestScenarios_Generation(t *testing.T) {
	scenarios := discoverScenarios(t)
	for _, name := range scenarios {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			inputPath := filepath.Join("scenarios", name, "input.tf")
			_, _, alsPath := buildAndGenerate(t, inputPath)

			info, err := os.Stat(alsPath)
			if err != nil {
				t.Fatalf("generated .als file not found: %v", err)
			}
			if info.Size() == 0 {
				t.Error("generated .als file is empty")
			}
		})
	}
}

// ── TestScenarios_Verification: requires Alloy JAR ───────────────────────────

// TestScenarios_Verification runs the full pipeline including Alloy model
// checking and compares results against expect.json.
// Skips automatically when the Alloy JAR is not found.
func TestScenarios_Verification(t *testing.T) {
	a := newAnalyzer(t)
	if !a.Available() {
		t.Skip("Alloy JAR not found at tools/org.alloytools.alloy.dist.jar; skipping verification")
	}

	scenarios := discoverScenarios(t)
	for _, name := range scenarios {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runScenarioVerification(t, name, a)
		})
	}
}

func runScenarioVerification(t *testing.T, name string, a *analyzer.Analyzer) {
	t.Helper()

	inputPath := filepath.Join("scenarios", name, "input.tf")
	expectPath := filepath.Join("scenarios", name, "expect.json")

	_, tripleKeys, alsPath := buildAndGenerate(t, inputPath)

	checks, err := a.Check(alsPath)
	if err != nil {
		t.Fatalf("Alloy check failed: %v", err)
	}

	results := reporter.BuildTripleResults(checks, tripleKeys)

	if *update {
		writeExpect(t, expectPath, name, results)
		return
	}

	compareResults(t, expectPath, results)
}

// ── Pipeline helpers ──────────────────────────────────────────────────────────

// buildAndGenerate runs parse → resolve → IR → generate and returns:
//   - the IR Config
//   - the TripleKey slice for this config
//   - the path to the generated .als file (in t.TempDir())
func buildAndGenerate(t *testing.T, inputPath string) (*ir.Config, []generator.TripleKey, string) {
	t.Helper()

	p := parser.NewParser()
	parseResult, err := p.ParseFile(inputPath)
	if err != nil {
		t.Fatalf("parse %s: %v", inputPath, err)
	}

	res := resolver.NewResolver()
	resources, err := res.Resolve(parseResult)
	if err != nil {
		t.Fatalf("resolve %s: %v", inputPath, err)
	}

	config, err := ir.BuildFromResources(resources, res.GetGraph())
	if err != nil {
		t.Fatalf("IR build %s: %v", inputPath, err)
	}

	gen := generator.NewGenerator(config, filepath.Base(inputPath))
	alsPath := filepath.Join(t.TempDir(), "spec.als")
	if err := gen.GenerateToFile(alsPath); err != nil {
		t.Fatalf("generate %s: %v", inputPath, err)
	}

	return config, gen.TripleMetadata(), alsPath
}

// ── Expect file helpers ───────────────────────────────────────────────────────

func writeExpect(t *testing.T, path, name string, results []*reporter.TripleResult) {
	t.Helper()
	ef := ExpectFile{SchemaVersion: 1, Name: name}
	for _, r := range results {
		q := ExpectQuery{
			Principal: r.Principal,
			Bucket:    r.Bucket,
			Action:    r.Action,
			Decision:  r.Decision,
			Layers:    make(map[string]string, 7),
		}
		if r.Decision == "DENY" {
			da := r.DeniedAtDesc
			q.DeniedAt = &da
		}
		for i, l := range r.Layers {
			q.Layers[fmt.Sprintf("L%d", i+1)] = l.Status
		}
		ef.Queries = append(ef.Queries, q)
	}
	data, err := json.MarshalIndent(ef, "", "  ")
	if err != nil {
		t.Fatalf("marshal expect.json: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write expect.json: %v", err)
	}
	t.Logf("Updated %s", path)
}

func compareResults(t *testing.T, expectPath string, results []*reporter.TripleResult) {
	t.Helper()

	data, err := os.ReadFile(expectPath)
	if err != nil {
		t.Fatalf("read expect.json: %v  (run with -update to generate it)", err)
	}
	var ef ExpectFile
	if err := json.Unmarshal(data, &ef); err != nil {
		t.Fatalf("parse expect.json: %v", err)
	}

	// Index actual results by triple key.
	byTriple := make(map[string]*reporter.TripleResult, len(results))
	for _, r := range results {
		byTriple[tripleKey(r.Principal, r.Bucket, r.Action)] = r
	}

	for _, eq := range ef.Queries {
		key := tripleKey(eq.Principal, eq.Bucket, eq.Action)
		r, ok := byTriple[key]
		if !ok {
			t.Errorf("expected triple %s not found in results", key)
			continue
		}

		if r.Decision != eq.Decision {
			t.Errorf("[%s] decision = %q, want %q", key, r.Decision, eq.Decision)
		}

		if eq.DeniedAt != nil && r.DeniedAtDesc != *eq.DeniedAt {
			t.Errorf("[%s] denied_at = %q, want %q", key, r.DeniedAtDesc, *eq.DeniedAt)
		}

		for lKey, wantStatus := range eq.Layers {
			idx := layerKeyIndex(lKey)
			if idx < 0 {
				t.Errorf("[%s] invalid layer key %q in expect.json", key, lKey)
				continue
			}
			got := r.Layers[idx].Status
			if got != wantStatus {
				t.Errorf("[%s] %s status = %q, want %q", key, lKey, got, wantStatus)
			}
		}
	}

	if len(results) != len(ef.Queries) {
		t.Errorf("result count = %d, want %d", len(results), len(ef.Queries))
	}
}

func tripleKey(principal, bucket, action string) string {
	return principal + "/" + bucket + "/" + action
}

// layerKeyIndex converts "L1"–"L7" to 0–6.
func layerKeyIndex(key string) int {
	if len(key) == 2 && key[0] == 'L' && key[1] >= '1' && key[1] <= '7' {
		return int(key[1] - '1')
	}
	return -1
}

// ── Scenario discovery ────────────────────────────────────────────────────────

func discoverScenarios(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir("scenarios")
	if err != nil {
		t.Fatalf("read scenarios dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatal("no scenario folders found under tests/scenarios/")
	}
	return names
}

// ── Analyzer construction ─────────────────────────────────────────────────────

// newAnalyzer builds an Analyzer whose JAR path resolves from the module root,
// so tests work correctly regardless of the working directory.
func newAnalyzer(t *testing.T) *analyzer.Analyzer {
	t.Helper()
	cwd, _ := os.Getwd()
	root := findModuleRoot(cwd)
	if root == "" {
		// Fallback to default auto-detection.
		return analyzer.New()
	}
	jarPath := filepath.Join(root, "tools", "org.alloytools.alloy.dist.jar")
	javaPath := findJava()
	return analyzer.NewWithPaths(javaPath, jarPath)
}

func findModuleRoot(start string) string {
	abs, err := filepath.Abs(start)
	if err != nil {
		return ""
	}
	dir := abs
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func findJava() string {
	if home := os.Getenv("JAVA_HOME"); home != "" {
		candidate := filepath.Join(home, "bin", "java")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	path, _ := exec.LookPath("java")
	return path
}
