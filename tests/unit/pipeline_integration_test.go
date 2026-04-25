package unit_test

import (
	"strings"
	"testing"

	"access-control-helper/internal/generator"
	"access-control-helper/internal/reporter"
)

func TestPipeline_AlloyResultsDriveReport(t *testing.T) {
	a := newAnalyzerForTest(t)
	if !a.Available() {
		t.Skip("Alloy JAR or Java not found; skipping")
	}

	checks, err := a.Check(fixtureAls(t, "identity_allow_only"))
	if err != nil {
		t.Fatalf("Alloy check failed: %v", err)
	}

	tripleKeys := generator.BuildTripleKeys(
		[]string{"app_role"},
		[]string{"my_bucket"},
		[]string{"S3_GetObject", "S3_PutObject", "S3_ListBucket", "S3_DeleteObject"},
	)

	results, err := reporter.BuildTripleResults(checks, tripleKeys)
	if err != nil {
		t.Fatalf("BuildTripleResults: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("reporter returned no results — expected one per triple")
	}

	byAction := make(map[string]*reporter.TripleResult, len(results))
	for _, r := range results {
		byAction[r.Action] = r
	}

	getObj, ok := byAction["S3_GetObject"]
	if !ok {
		t.Fatal("no result for S3_GetObject")
	}
	if getObj.Decision != "ALLOW" {
		t.Errorf("S3_GetObject: decision = %q, want ALLOW (identity policy grants it)", getObj.Decision)
	}

	for _, action := range []string{"S3_PutObject", "S3_ListBucket", "S3_DeleteObject"} {
		r, ok := byAction[action]
		if !ok {
			t.Errorf("no result for %s", action)
			continue
		}
		if r.Decision != "DENY" {
			t.Errorf("%s: decision = %q, want DENY (implicit deny — not in identity policy)", action, r.Decision)
		}
		if r.Layers[4].Status != "NOT GRANTED" {
			t.Errorf("%s: Layer 5 = %q, want NOT GRANTED", action, r.Layers[4].Status)
		}
	}
}

func TestPipeline_ReportOutputReflectsAlloyDecisions(t *testing.T) {
	a := newAnalyzerForTest(t)
	if !a.Available() {
		t.Skip("Alloy JAR or Java not found; skipping")
	}

	checks, err := a.Check(fixtureAls(t, "identity_allow_only"))
	if err != nil {
		t.Fatalf("Alloy check failed: %v", err)
	}

	tripleKeys := generator.BuildTripleKeys(
		[]string{"app_role"},
		[]string{"my_bucket"},
		[]string{"S3_GetObject", "S3_DeleteObject"},
	)

	results, err := reporter.BuildTripleResults(checks, tripleKeys)
	if err != nil {
		t.Fatalf("BuildTripleResults: %v", err)
	}

	var sb strings.Builder
	rep := reporter.New(&sb)
	rep.Summary(results)
	rep.Report(results)
	out := sb.String()

	if !strings.Contains(out, "ALLOW") {
		t.Error("report output missing ALLOW — expected for S3_GetObject")
	}
	if !strings.Contains(out, "DENY") {
		t.Error("report output missing DENY — expected for S3_DeleteObject")
	}
	if !strings.Contains(out, `can "app_role" perform s3:GetObject on "my_bucket"`) {
		t.Error("report missing query line for s3:GetObject")
	}
	if !strings.Contains(out, "NOT GRANTED") {
		t.Error("report missing NOT GRANTED — expected at Layer 5 for denied actions")
	}
}

func TestPipeline_ReportDecisionsAreNotHardcoded(t *testing.T) {
	a := newAnalyzerForTest(t)
	if !a.Available() {
		t.Skip("Alloy JAR or Java not found; skipping")
	}

	checks, err := a.Check(fixtureAls(t, "identity_allow_only"))
	if err != nil {
		t.Fatalf("Alloy check failed: %v", err)
	}

	tripleKeys := generator.BuildTripleKeys(
		[]string{"app_role"},
		[]string{"my_bucket"},
		[]string{"S3_GetObject", "S3_DeleteObject"},
	)

	results, err := reporter.BuildTripleResults(checks, tripleKeys)
	if err != nil {
		t.Fatalf("BuildTripleResults: %v", err)
	}

	allowCount := 0
	denyCount := 0
	for _, r := range results {
		if r.Decision == "ALLOW" {
			allowCount++
		} else {
			denyCount++
		}
	}

	if allowCount == 0 {
		t.Error("no ALLOW results — decisions appear hardcoded to DENY")
	}
	if denyCount == 0 {
		t.Error("no DENY results — decisions appear hardcoded to ALLOW")
	}
	if allowCount == len(results) {
		t.Error("all results are ALLOW — Alloy DENY output is not being respected")
	}
	if denyCount == len(results) {
		t.Error("all results are DENY — Alloy ALLOW output is not being respected")
	}
}
