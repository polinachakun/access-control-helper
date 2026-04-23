// Package e2e_test – reporter snapshot tests.
//
// These tests protect the human-readable report formatting against regressions.
// One snapshot per distinct verdict type covers all formatting branches in reporter.go:
//
//  1. ALLOW
//  2. DENY at a blocking layer (Layer 1 – explicit deny)
//  3. DENY at a grant layer (Layer 4/5 – no grant path)
//  4. DENY at a bounding layer (Layer 6 – permission boundary)
//
// To update all snapshots after an intentional formatting change:
//
//	go test ./tests/ -run TestReportSnapshot -update-snapshots
package e2e_test

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"access-control-helper/internal/reporter"
)

var updateSnapshots = flag.Bool("update-snapshots", false, "overwrite golden snapshot files")

// ── snapshot helpers ──────────────────────────────────────────────────────────

// snapshotPath returns the path for a named golden file.
func snapshotPath(name string) string {
	return filepath.Join("testdata", "snapshots", name+".golden.txt")
}

// checkSnapshot compares got against the named golden file.
// If -update-snapshots is set, it writes got as the new golden file.
func checkSnapshot(t *testing.T, name, got string) {
	t.Helper()
	path := snapshotPath(name)

	if *updateSnapshots {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("mkdir snapshots: %v", err)
		}
		if err := os.WriteFile(path, []byte(got), 0644); err != nil {
			t.Fatalf("write snapshot %s: %v", path, err)
		}
		t.Logf("Updated snapshot: %s", path)
		return
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read snapshot %s: %v  (run with -update-snapshots to create it)", path, err)
	}
	want := string(data)
	if got != want {
		t.Errorf("snapshot %s mismatch.\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}

// ── TripleResult constructors ─────────────────────────────────────────────────

func allowResult(principal, bucket, action string) *reporter.TripleResult {
	r := &reporter.TripleResult{
		Principal: principal,
		Bucket:    bucket,
		Action:    action,
		Decision:  "ALLOW",
	}
	for i := range r.Layers {
		r.Layers[i].Status = "PASS"
	}
	return r
}

func denyLayer1Result(principal, bucket, action string) *reporter.TripleResult {
	r := &reporter.TripleResult{
		Principal:    principal,
		Bucket:       bucket,
		Action:       action,
		Decision:     "DENY",
		DeniedAtDesc: "Layer 1",
	}
	r.Layers[0].Status = "DENY"
	for i := 1; i < 7; i++ {
		r.Layers[i].Status = "PASS"
	}
	// Granting layers use NOT GRANTED on failure, but here they pass.
	return r
}

func denyLayer45Result(principal, bucket, action string) *reporter.TripleResult {
	r := &reporter.TripleResult{
		Principal:    principal,
		Bucket:       bucket,
		Action:       action,
		Decision:     "DENY",
		DeniedAtDesc: "Layer 4/5",
	}
	for i := range r.Layers {
		r.Layers[i].Status = "PASS"
	}
	r.Layers[3].Status = "NOT GRANTED" // L4
	r.Layers[4].Status = "NOT GRANTED" // L5
	return r
}

func denyLayer6Result(principal, bucket, action string) *reporter.TripleResult {
	r := &reporter.TripleResult{
		Principal:    principal,
		Bucket:       bucket,
		Action:       action,
		Decision:     "DENY",
		DeniedAtDesc: "Layer 6",
	}
	for i := range r.Layers {
		r.Layers[i].Status = "PASS"
	}
	r.Layers[5].Status = "DENY" // L6
	return r
}

// render produces the Report output as a string.
func render(results []*reporter.TripleResult) string {
	var sb strings.Builder
	reporter.New(&sb).Report(results)
	return sb.String()
}

// ── Snapshot tests ────────────────────────────────────────────────────────────

func TestReportSnapshot_Allow(t *testing.T) {
	result := allowResult("app_role", "my_bucket", "S3_GetObject")
	got := render([]*reporter.TripleResult{result})
	checkSnapshot(t, "allow", got)
}

func TestReportSnapshot_DenyAtLayer1(t *testing.T) {
	result := denyLayer1Result("app_role", "my_bucket", "S3_DeleteObject")
	got := render([]*reporter.TripleResult{result})
	checkSnapshot(t, "deny_layer1", got)
}

func TestReportSnapshot_DenyAtLayer45(t *testing.T) {
	result := denyLayer45Result("app_role", "my_bucket", "S3_PutObject")
	got := render([]*reporter.TripleResult{result})
	checkSnapshot(t, "deny_layer45", got)
}

func TestReportSnapshot_DenyAtLayer6(t *testing.T) {
	result := denyLayer6Result("restricted_role", "secure_bucket", "S3_PutObject")
	got := render([]*reporter.TripleResult{result})
	checkSnapshot(t, "deny_layer6", got)
}
