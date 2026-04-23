package unit_test

import (
	"strings"
	"testing"

	"access-control-helper/internal/analyzer"
	"access-control-helper/internal/generator"
	"access-control-helper/internal/reporter"
)

func makeKey(role, bucket, action string) generator.TripleKey {
	keys := generator.BuildTripleKeys([]string{role}, []string{bucket}, []string{action})
	return keys[0]
}

func makeChecks(key generator.TripleKey, combinedValid bool, layerValid [7]bool) []analyzer.CheckResult {
	checks := []analyzer.CheckResult{
		{Name: key.AssertionBaseName, Valid: combinedValid},
	}
	for i, lp := range generator.LayerPredicates {
		checks = append(checks, analyzer.CheckResult{
			Name:  key.AssertionBaseName + lp.Suffix,
			Valid: layerValid[i],
		})
	}
	return checks
}

func allPass() [7]bool { return [7]bool{true, true, true, true, true, true, true} }

func TestBuildTripleResults_Allow(t *testing.T) {
	key := makeKey("app_role", "my_bucket", "S3_GetObject")
	checks := makeChecks(key, true, allPass())

	results := reporter.BuildTripleResults(checks, []generator.TripleKey{key})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Decision != "ALLOW" {
		t.Errorf("Decision = %q, want ALLOW", r.Decision)
	}
	if r.Principal != "app_role" {
		t.Errorf("Principal = %q, want app_role", r.Principal)
	}
	if r.Bucket != "my_bucket" {
		t.Errorf("Bucket = %q, want my_bucket", r.Bucket)
	}
	if r.Action != "S3_GetObject" {
		t.Errorf("Action = %q, want S3_GetObject", r.Action)
	}
	for i, layer := range r.Layers {
		if layer.Status != "PASS" {
			t.Errorf("Layer[%d] Status = %q, want PASS", i, layer.Status)
		}
	}
}

func TestBuildTripleResults_DenyAtLayer1(t *testing.T) {
	key := makeKey("app_role", "my_bucket", "S3_DeleteObject")
	layers := allPass()
	layers[0] = false

	checks := makeChecks(key, false, layers)
	results := reporter.BuildTripleResults(checks, []generator.TripleKey{key})

	r := results[0]
	if r.Decision != "DENY" {
		t.Errorf("Decision = %q, want DENY", r.Decision)
	}
	if r.Layers[0].Status != "DENY" {
		t.Errorf("L1 Status = %q, want DENY", r.Layers[0].Status)
	}
	if r.DeniedAtDesc != "Layer 1" {
		t.Errorf("DeniedAtDesc = %q, want Layer 1", r.DeniedAtDesc)
	}
}

func TestBuildTripleResults_DenyAtLayer6(t *testing.T) {
	key := makeKey("restricted_role", "secure_bucket", "S3_PutObject")
	layers := allPass()
	layers[5] = false

	checks := makeChecks(key, false, layers)
	results := reporter.BuildTripleResults(checks, []generator.TripleKey{key})

	r := results[0]
	if r.Decision != "DENY" {
		t.Errorf("Decision = %q, want DENY", r.Decision)
	}
	if r.Layers[5].Status != "DENY" {
		t.Errorf("L6 Status = %q, want DENY", r.Layers[5].Status)
	}
	if r.DeniedAtDesc != "Layer 6" {
		t.Errorf("DeniedAtDesc = %q, want Layer 6", r.DeniedAtDesc)
	}
}

func TestBuildTripleResults_DenyAtLayer45(t *testing.T) {
	key := makeKey("app_role", "my_bucket", "S3_PutObject")
	layers := allPass()
	layers[3] = false
	layers[4] = false

	checks := makeChecks(key, false, layers)
	results := reporter.BuildTripleResults(checks, []generator.TripleKey{key})

	r := results[0]
	if r.Decision != "DENY" {
		t.Errorf("Decision = %q, want DENY", r.Decision)
	}
	if r.Layers[3].Status != "NOT GRANTED" {
		t.Errorf("L4 Status = %q, want NOT GRANTED", r.Layers[3].Status)
	}
	if r.Layers[4].Status != "NOT GRANTED" {
		t.Errorf("L5 Status = %q, want NOT GRANTED", r.Layers[4].Status)
	}
	if r.DeniedAtDesc != "Layer 4/5" {
		t.Errorf("DeniedAtDesc = %q, want Layer 4/5", r.DeniedAtDesc)
	}
}

func TestBuildTripleResults_DenyAtLayer5Only(t *testing.T) {
	key := makeKey("app_role", "my_bucket", "S3_PutObject")
	layers := allPass()
	layers[4] = false

	checks := makeChecks(key, false, layers)
	results := reporter.BuildTripleResults(checks, []generator.TripleKey{key})

	r := results[0]
	if r.DeniedAtDesc != "Layer 5" {
		t.Errorf("DeniedAtDesc = %q, want Layer 5", r.DeniedAtDesc)
	}
}

func TestBuildTripleResults_BlockingPlusNoGrant_AdditionalFinding(t *testing.T) {
	key := makeKey("app_role", "my_bucket", "S3_DeleteObject")
	layers := allPass()
	layers[0] = false
	layers[3] = false
	layers[4] = false

	checks := makeChecks(key, false, layers)
	results := reporter.BuildTripleResults(checks, []generator.TripleKey{key})

	r := results[0]
	if r.DeniedAtDesc != "Layer 1" {
		t.Errorf("DeniedAtDesc = %q, want Layer 1 (blocking wins)", r.DeniedAtDesc)
	}
	if len(r.AdditionalFindings) == 0 {
		t.Error("expected additional findings when both blocking layer and grant layers fail")
	}
}

func TestBuildTripleResults_MultipleTriples(t *testing.T) {
	k1 := makeKey("app_role", "my_bucket", "S3_GetObject")
	k2 := makeKey("app_role", "my_bucket", "S3_DeleteObject")

	layers2 := allPass()
	layers2[0] = false

	checks := append(
		makeChecks(k1, true, allPass()),
		makeChecks(k2, false, layers2)...,
	)
	results := reporter.BuildTripleResults(checks, []generator.TripleKey{k1, k2})

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Decision != "ALLOW" {
		t.Errorf("result[0].Decision = %q, want ALLOW", results[0].Decision)
	}
	if results[1].Decision != "DENY" {
		t.Errorf("result[1].Decision = %q, want DENY", results[1].Decision)
	}
}

func TestBuildTripleResults_MissingCheckDefaultsToDeny(t *testing.T) {
	key := makeKey("app_role", "my_bucket", "S3_GetObject")
	results := reporter.BuildTripleResults(nil, []generator.TripleKey{key})
	if len(results) != 1 {
		t.Fatalf("expected 1 result even with no checks, got %d", len(results))
	}
	if results[0].Decision != "DENY" {
		t.Errorf("missing combined check should default to DENY, got %q", results[0].Decision)
	}
}

func TestReport_Allow_ContainsExpectedLines(t *testing.T) {
	result := &reporter.TripleResult{
		Principal: "app_role",
		Bucket:    "my_bucket",
		Action:    "S3_GetObject",
		Decision:  "ALLOW",
	}
	for i := range result.Layers {
		result.Layers[i].Status = "PASS"
	}

	var sb strings.Builder
	rep := reporter.New(&sb)
	rep.Report([]*reporter.TripleResult{result})
	out := sb.String()

	mustContainStr(t, out, `Query: can "app_role" perform s3:GetObject on "my_bucket"?`)
	mustContainStr(t, out, "Result: ALLOW")
	mustContainStr(t, out, "PASS")
}

func TestReport_Deny_ContainsDeniedAt(t *testing.T) {
	result := &reporter.TripleResult{
		Principal:    "app_role",
		Bucket:       "my_bucket",
		Action:       "S3_DeleteObject",
		Decision:     "DENY",
		DeniedAtDesc: "Layer 1",
	}
	result.Layers[0].Status = "DENY"
	for i := 1; i < 7; i++ {
		result.Layers[i].Status = "PASS"
	}

	var sb strings.Builder
	reporter.New(&sb).Report([]*reporter.TripleResult{result})
	out := sb.String()

	mustContainStr(t, out, "Result: DENY at Layer 1")
	mustContainStr(t, out, "DENY")
}

func TestReport_Empty_NoResults(t *testing.T) {
	var sb strings.Builder
	reporter.New(&sb).Report(nil)
	out := sb.String()
	mustContainStr(t, out, "No (principal, bucket, action) triples found")
}

func TestSummary_ContainsHeaders(t *testing.T) {
	result := &reporter.TripleResult{
		Principal: "app_role",
		Bucket:    "my_bucket",
		Action:    "S3_GetObject",
		Decision:  "ALLOW",
	}
	var sb strings.Builder
	reporter.New(&sb).Summary([]*reporter.TripleResult{result})
	out := sb.String()
	mustContainStr(t, out, "Principal")
	mustContainStr(t, out, "Action")
	mustContainStr(t, out, "Bucket")
	mustContainStr(t, out, "Decision")
}

func TestSummary_DenyShowsLayer(t *testing.T) {
	result := &reporter.TripleResult{
		Principal:    "restricted_role",
		Bucket:       "secure_bucket",
		Action:       "S3_PutObject",
		Decision:     "DENY",
		DeniedAtDesc: "Layer 6",
	}
	var sb strings.Builder
	reporter.New(&sb).Summary([]*reporter.TripleResult{result})
	out := sb.String()
	mustContainStr(t, out, "DENY at Layer 6")
}

func TestSummary_Empty_NoOutput(t *testing.T) {
	var sb strings.Builder
	reporter.New(&sb).Summary(nil)
	if sb.Len() != 0 {
		t.Errorf("Summary with nil results should produce no output, got %q", sb.String())
	}
}

func mustContainStr(t *testing.T, s, substr string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Errorf("output missing %q\n--- output ---\n%s", substr, s)
	}
}
