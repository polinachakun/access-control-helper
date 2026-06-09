// Scalability benchmark for the access-control-helper Alloy pipeline.
//
// Usage:
//
//	go test ./evaluation/scalability/ -v -timeout 30m
//	go test ./evaluation/scalability/ -v -timeout 30m -run TestScalabilityDimensions
//	go test ./evaluation/scalability/ -v -timeout 30m -run TestScalabilityTriples
package scalability_test

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"access-control-helper/internal/analyzer"
	"access-control-helper/internal/generator"
	"access-control-helper/internal/ir"
	"access-control-helper/internal/parser"
	"access-control-helper/internal/resolver"
)

// supportedActions is the ordered list of S3 actions used in experiments.
var supportedActions = []string{
	"s3:GetObject",
	"s3:PutObject",
	"s3:ListBucket",
	"s3:DeleteObject",
}

// ── Synthetic TF generator ────────────────────────────────────────────────────

// synthTF produces a minimal valid Terraform config with:
//   - `principals` IAM roles, each with an inline policy allowing `actions`
//   - `buckets` S3 buckets (no bucket policies — identity-policy-only scenario)
func synthTF(principals, buckets int, actions []string) string {
	var sb strings.Builder
	actionJSON := `["` + strings.Join(actions, `", "`) + `"]`

	for i := 0; i < principals; i++ {
		name := fmt.Sprintf("role_%d", i)
		sb.WriteString(fmt.Sprintf(`
resource "aws_iam_role" "%s" {
  name = "%s"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole",
                   Principal = { Service = "ec2.amazonaws.com" } }]
  })
}
resource "aws_iam_policy" "policy_%d" {
  name   = "policy-%d"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = %s, Resource = "*" }]
  })
}
resource "aws_iam_role_policy_attachment" "attach_%d" {
  role       = aws_iam_role.%s.name
  policy_arn = aws_iam_policy.policy_%d.arn
}
`, name, name, i, i, actionJSON, i, name, i))
	}

	for i := 0; i < buckets; i++ {
		sb.WriteString(fmt.Sprintf(`
resource "aws_s3_bucket" "bucket_%d" {
  bucket = "bench-bucket-%d"
}
`, i, i))
	}

	return sb.String()
}

// ── Pipeline runner ───────────────────────────────────────────────────────────

type runResult struct {
	TotalMs int64
	AlsPath string
	Err     error
}

func runPipeline(t *testing.T, tfContent, jarPath string) runResult {
	t.Helper()

	dir := t.TempDir()
	tfPath := filepath.Join(dir, "bench.tf")
	alsPath := filepath.Join(dir, "bench.als")

	if err := os.WriteFile(tfPath, []byte(tfContent), 0o644); err != nil {
		return runResult{Err: err}
	}

	start := time.Now()

	p := parser.NewParser()
	parseResult, err := p.ParseFiles([]string{tfPath})
	if err != nil {
		return runResult{Err: fmt.Errorf("parse: %w", err)}
	}

	res := resolver.NewResolver()
	resolved, err := res.Resolve(parseResult)
	if err != nil {
		return runResult{Err: fmt.Errorf("resolve: %w", err)}
	}

	b := ir.NewBuilder(resolved, res.GetGraph())
	cfg, err := b.Build()
	if err != nil {
		return runResult{Err: fmt.Errorf("ir: %w", err)}
	}

	gen := generator.NewGenerator(cfg, tfPath)
	if err := gen.GenerateToFile(alsPath); err != nil {
		return runResult{Err: fmt.Errorf("generate: %w", err)}
	}

	a := analyzer.NewWithPaths(findJava(), jarPath)
	if _, err := a.Check(alsPath); err != nil {
		return runResult{Err: fmt.Errorf("alloy: %w", err)}
	}

	return runResult{TotalMs: time.Since(start).Milliseconds(), AlsPath: alsPath}
}

// ── CSV writer ────────────────────────────────────────────────────────────────

type csvRow struct {
	Experiment string
	Label      string
	Principals int
	Buckets    int
	Actions    int
	Triples    int
	Assertions int
	ElapsedMs  int64
	Status     string
}

func writeCSV(path string, rows []csvRow) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	_ = w.Write([]string{
		"experiment", "label",
		"principals", "buckets", "actions",
		"triples", "assertions", "elapsed_ms", "status",
	})
	for _, r := range rows {
		_ = w.Write([]string{
			r.Experiment, r.Label,
			strconv.Itoa(r.Principals),
			strconv.Itoa(r.Buckets),
			strconv.Itoa(r.Actions),
			strconv.Itoa(r.Triples),
			strconv.Itoa(r.Assertions),
			strconv.FormatInt(r.ElapsedMs, 10),
			r.Status,
		})
	}
	w.Flush()
	return w.Error()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func jarPath(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	jar := filepath.Join(root, "tools", "org.alloytools.alloy.dist.jar")
	if _, err := os.Stat(jar); err != nil {
		t.Skip("Alloy JAR not found, skipping scalability benchmark")
	}
	return jar
}

func findJava() string {
	return "java"
}

func resultsPath(name string) string {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(file), "results")
	_ = os.MkdirAll(dir, 0o755)
	ts := time.Now().Format("20060102_150405")
	return filepath.Join(dir, fmt.Sprintf("%s_%s.csv", name, ts))
}

// ── Experiment 1: Dimension isolation ────────────────────────────────────────
//
// Fixes two dimensions and varies the third. Shows individual impact of each
// dimension (principals, buckets, actions) on execution time.

func TestScalabilityDimensions(t *testing.T) {
	jar := jarPath(t)
	var rows []csvRow

	type dimPoint struct {
		P, B, A int
	}

	experiments := map[string][]dimPoint{
		"vary_principals": {
			{1, 1, 1}, {2, 1, 1}, {3, 1, 1}, {4, 1, 1}, {5, 1, 1}, {6, 1, 1},
		},
		"vary_buckets": {
			{1, 1, 1}, {1, 2, 1}, {1, 3, 1}, {1, 4, 1}, {1, 5, 1}, {1, 6, 1},
		},
		"vary_actions": {
			{1, 1, 1}, {1, 1, 2}, {1, 1, 3}, {1, 1, 4},
		},
	}

	for expName, points := range experiments {
		for _, pt := range points {
			actions := supportedActions[:pt.A]
			tf := synthTF(pt.P, pt.B, actions)
			triples := pt.P * pt.B * pt.A

			label := fmt.Sprintf("P%d_B%d_A%d", pt.P, pt.B, pt.A)
			t.Logf("[%s] %s — %d triples", expName, label, triples)

			res := runPipeline(t, tf, jar)
			status := "ok"
			if res.Err != nil {
				status = "error: " + res.Err.Error()
				t.Logf("  ERROR: %v", res.Err)
			} else {
				t.Logf("  elapsed: %d ms", res.TotalMs)
			}

			rows = append(rows, csvRow{
				Experiment: expName,
				Label:      label,
				Principals: pt.P,
				Buckets:    pt.B,
				Actions:    pt.A,
				Triples:    triples,
				Assertions: triples * 8,
				ElapsedMs:  res.TotalMs,
				Status:     status,
			})
		}
	}

	out := resultsPath("dimensions")
	if err := writeCSV(out, rows); err != nil {
		t.Fatalf("write CSV: %v", err)
	}
	t.Logf("Results written to %s", out)
}

// ── Experiment 2: Triple count scaling ───────────────────────────────────────
//
// Varies P × B × A together across a range of triple counts.
// Used to fit a scaling curve and identify practical limits.

func TestScalabilityTriples(t *testing.T) {
	jar := jarPath(t)

	type point struct {
		P, B, A int
	}

	// Combinations chosen to cover triples: 1, 2, 4, 8, 12, 18, 24, 32, 48, 64, 96, 128
	points := []point{
		{1, 1, 1}, // 1
		{2, 1, 1}, // 2
		{2, 2, 1}, // 4
		{2, 2, 2}, // 8
		{3, 2, 2}, // 12
		{3, 3, 2}, // 18
		{4, 3, 2}, // 24
		{4, 4, 2}, // 32
		{4, 4, 3}, // 48
		{4, 4, 4}, // 64
		{6, 4, 4}, // 96
		{4, 4, 4}, // 64 repeated for variance check
		{8, 4, 4}, // 128 — may be slow
	}

	out := resultsPath("triples")
	f, err := os.Create(out)
	if err != nil {
		t.Fatalf("create CSV: %v", err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write([]string{
		"experiment", "label",
		"principals", "buckets", "actions",
		"triples", "assertions", "elapsed_ms", "status",
	})
	w.Flush()

	for _, pt := range points {
		actions := supportedActions[:pt.A]
		tf := synthTF(pt.P, pt.B, actions)
		triples := pt.P * pt.B * pt.A

		label := fmt.Sprintf("P%d_B%d_A%d", pt.P, pt.B, pt.A)
		t.Logf("[triples=%d] %s", triples, label)

		res := runPipeline(t, tf, jar)
		status := "ok"
		if res.Err != nil {
			status = "error: " + res.Err.Error()
			t.Logf("  ERROR: %v", res.Err)
		} else {
			t.Logf("  elapsed: %d ms", res.TotalMs)
		}

		_ = w.Write([]string{
			"triples", label,
			strconv.Itoa(pt.P), strconv.Itoa(pt.B), strconv.Itoa(pt.A),
			strconv.Itoa(triples), strconv.Itoa(triples * 8),
			strconv.FormatInt(res.TotalMs, 10), status,
		})
		w.Flush()
	}

	t.Logf("Results written to %s", out)
}

// ── Experiment 3: Full P×B heatmap at fixed A ─────────────────────────────────
//
// Runs every combination of P=[1..6] × B=[1..6] with A=2 fixed.
// Produces a complete grid for the heatmap visualisation.

func TestScalabilityHeatmap(t *testing.T) {
	jar := jarPath(t)
	const fixedA = 2
	actions := supportedActions[:fixedA]

	out := resultsPath("heatmap")
	f, err := os.Create(out)
	if err != nil {
		t.Fatalf("create CSV: %v", err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write([]string{
		"experiment", "label",
		"principals", "buckets", "actions",
		"triples", "assertions", "elapsed_ms", "status",
	})
	w.Flush()

	for p := 1; p <= 6; p++ {
		for b := 1; b <= 5; b++ {
			triples := p * b * fixedA
			label := fmt.Sprintf("P%d_B%d_A%d", p, b, fixedA)
			t.Logf("[heatmap] %s — %d triples", label, triples)

			tf := synthTF(p, b, actions)
			res := runPipeline(t, tf, jar)
			status := "ok"
			if res.Err != nil {
				status = "error: " + res.Err.Error()
				t.Logf("  ERROR: %v", res.Err)
			} else {
				t.Logf("  elapsed: %d ms", res.TotalMs)
			}

			_ = w.Write([]string{
				"heatmap", label,
				strconv.Itoa(p), strconv.Itoa(b), strconv.Itoa(fixedA),
				strconv.Itoa(triples), strconv.Itoa(triples * 8),
				strconv.FormatInt(res.TotalMs, 10), status,
			})
			w.Flush()
		}
	}

	t.Logf("Results written to %s", out)
}
