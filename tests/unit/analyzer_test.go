package unit_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"access-control-helper/internal/analyzer"
)

func findModuleRoot(t *testing.T) string {
	t.Helper()
	cwd, _ := os.Getwd()
	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate module root (go.mod not found)")
		}
		dir = parent
	}
}

func newAnalyzerForTest(t *testing.T) *analyzer.Analyzer {
	t.Helper()
	root := findModuleRoot(t)
	jarPath := filepath.Join(root, "tools", "org.alloytools.alloy.dist.jar")
	javaPath, _ := exec.LookPath("java")
	if home := os.Getenv("JAVA_HOME"); home != "" {
		candidate := filepath.Join(home, "bin", "java")
		if _, err := os.Stat(candidate); err == nil {
			javaPath = candidate
		}
	}
	return analyzer.NewWithPaths(javaPath, jarPath)
}

func fixtureAls(t *testing.T, name string) string {
	t.Helper()
	root := findModuleRoot(t)
	path := filepath.Join(root, "tests", "testdata", "alloy", name+".als")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fixture not found: %s", path)
	}
	return path
}

func TestAnalyzer_Available(t *testing.T) {
	a := newAnalyzerForTest(t)
	if !a.Available() {
		t.Skip("Alloy JAR or Java not found; skipping")
	}
}

func TestAnalyzer_ReturnsResultsFromAlloy(t *testing.T) {
	a := newAnalyzerForTest(t)
	if !a.Available() {
		t.Skip("Alloy JAR or Java not found; skipping")
	}

	results, err := a.Check(fixtureAls(t, "identity_allow_only"))
	if err != nil {
		t.Fatalf("analyzer.Check failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("Alloy returned no check results — expected at least one")
	}
}

func TestAnalyzer_ResultCountMatchesAssertions(t *testing.T) {
	a := newAnalyzerForTest(t)
	if !a.Available() {
		t.Skip("Alloy JAR or Java not found; skipping")
	}

	alsPath := fixtureAls(t, "identity_allow_only")

	data, err := os.ReadFile(alsPath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	assertionCount := strings.Count(string(data), "\ncheck ")

	results, err := a.Check(alsPath)
	if err != nil {
		t.Fatalf("analyzer.Check failed: %v", err)
	}

	if len(results) != assertionCount {
		t.Errorf("Alloy returned %d results, want %d (one per check command)", len(results), assertionCount)
	}
}

func TestAnalyzer_ResultNamesMatchAssertionNames(t *testing.T) {
	a := newAnalyzerForTest(t)
	if !a.Available() {
		t.Skip("Alloy JAR or Java not found; skipping")
	}

	results, err := a.Check(fixtureAls(t, "identity_allow_only"))
	if err != nil {
		t.Fatalf("analyzer.Check failed: %v", err)
	}

	for _, r := range results {
		if r.Name == "" {
			t.Error("CheckResult has empty Name — Alloy output was not parsed correctly")
		}
		if !strings.HasPrefix(r.Name, "AppRole") {
			t.Errorf("unexpected assertion name %q — expected AppRole* prefix", r.Name)
		}
	}
}

func TestAnalyzer_GetObjectIsValid_OthersAreNot(t *testing.T) {
	a := newAnalyzerForTest(t)
	if !a.Available() {
		t.Skip("Alloy JAR or Java not found; skipping")
	}

	results, err := a.Check(fixtureAls(t, "identity_allow_only"))
	if err != nil {
		t.Fatalf("analyzer.Check failed: %v", err)
	}

	byName := make(map[string]bool, len(results))
	for _, r := range results {
		byName[r.Name] = r.Valid
	}

	if valid, ok := byName["AppRoleCanGetObjectOnMyBucket"]; !ok {
		t.Error("expected assertion AppRoleCanGetObjectOnMyBucket not found in Alloy output")
	} else if !valid {
		t.Error("AppRoleCanGetObjectOnMyBucket should be Valid=true (ALLOW)")
	}

	denied := []string{
		"AppRoleCanDeleteObjectOnMyBucket",
		"AppRoleCanPutObjectOnMyBucket",
		"AppRoleCanListBucketOnMyBucket",
	}
	for _, name := range denied {
		if valid, ok := byName[name]; !ok {
			t.Errorf("expected assertion %q not found in Alloy output", name)
		} else if valid {
			t.Errorf("%q should be Valid=false (DENY — implicit deny)", name)
		}
	}
}

func TestAnalyzer_EachResultHasValidOrCounterExample(t *testing.T) {
	a := newAnalyzerForTest(t)
	if !a.Available() {
		t.Skip("Alloy JAR or Java not found; skipping")
	}

	results, err := a.Check(fixtureAls(t, "identity_allow_only"))
	if err != nil {
		t.Fatalf("analyzer.Check failed: %v", err)
	}

	for _, r := range results {
		if r.Valid == r.HasCounterExample {
			t.Errorf("[%s] Valid=%v and HasCounterExample=%v must be mutually exclusive",
				r.Name, r.Valid, r.HasCounterExample)
		}
	}
}
