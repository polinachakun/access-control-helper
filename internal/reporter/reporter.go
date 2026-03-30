// Package reporter formats the output of the Go evaluator and (optionally) the
// Alloy model checker into a human-readable access analysis report.
package reporter

import (
	"fmt"
	"io"
	"strings"

	"access-control-helper/internal/analyzer"
	"access-control-helper/internal/evaluator"
)

const (
	sectionWidth = 62
	colHeader    = 38 // width of the "Layer N — Name:" column
)

// Reporter writes analysis results to an io.Writer.
type Reporter struct {
	w io.Writer
}

// New creates a Reporter that writes to w.
func New(w io.Writer) *Reporter { return &Reporter{w: w} }

// Report writes the full analysis: per-triple layer breakdown and optional
// Alloy verification results.
func (r *Reporter) Report(results []*evaluator.EvaluationResult, checkResults []analyzer.CheckResult) {
	r.header("Access Analysis Report")

	if len(results) == 0 {
		fmt.Fprintln(r.w, "No (principal, bucket, action) triples found — nothing to analyse.")
		return
	}

	for _, res := range results {
		r.reportTriple(res)
	}

	if len(checkResults) > 0 {
		r.header("Alloy Formal Verification")
		r.reportAlloyResults(checkResults)
	}
}

var layerNames = [7]string{
	"Layer 1 — Deny Evaluation",
	"Layer 2 — RCP",
	"Layer 3 — SCP",
	"Layer 4 — Resource Policy",
	"Layer 5 — Identity Policy",
	"Layer 6 — Permission Boundary",
	"Layer 7 — Session Policy",
}

func (r *Reporter) reportTriple(res *evaluator.EvaluationResult) {
	fmt.Fprintf(r.w, "\nQuery: can %q perform %s on %q?\n",
		res.PrincipalName, res.Action, res.BucketName)
	fmt.Fprintln(r.w, strings.Repeat("─", sectionWidth))

	for i, layer := range res.Layers {
		label := layerNames[i] + ":"
		status := layer.Status.String()

		fmt.Fprintf(r.w, "  %-*s %s\n", colHeader, label, status)
		if layer.Status == evaluator.LayerDeny && layer.Reason != "" {
			fmt.Fprintf(r.w, "    → %s\n", layer.Reason)
		}
	}

	fmt.Fprintln(r.w)
	if res.Final == evaluator.DecisionAllow {
		fmt.Fprintln(r.w, "  Result: ALLOW")
	} else {
		fmt.Fprintf(r.w, "  Result: DENY at Layer %d\n", res.DeniedAtLayer)
		if res.DeniedReason != "" {
			fmt.Fprintf(r.w, "    → %s\n", res.DeniedReason)
		}
	}
	fmt.Fprintln(r.w)
}

func (r *Reporter) reportAlloyResults(results []analyzer.CheckResult) {
	fmt.Fprintln(r.w)
	fmt.Fprintf(r.w, "  %-50s  %s\n", "Assertion", "Status")
	fmt.Fprintf(r.w, "  %s  %s\n", strings.Repeat("─", 50), strings.Repeat("─", 30))

	for _, cr := range results {
		status := "UNKNOWN"
		switch {
		case cr.Valid:
			status = "PASS — no counterexample found"
		case cr.HasCounterExample:
			status = "FAIL — counterexample found (DENY)"
		}
		fmt.Fprintf(r.w, "  %-50s  %s\n", cr.Name, status)
	}
	fmt.Fprintln(r.w)
}

func (r *Reporter) Summary(results []*evaluator.EvaluationResult) {
	if len(results) == 0 {
		return
	}

	r.header("Access Summary")
	fmt.Fprintf(r.w, "  %-25s %-20s %-22s %s\n", "Principal", "Action", "Bucket", "Decision")
	fmt.Fprintf(r.w, "  %s %s %s %s\n",
		strings.Repeat("─", 25), strings.Repeat("─", 20),
		strings.Repeat("─", 22), strings.Repeat("─", 20))

	for _, res := range results {
		decision := res.Final.String()
		if res.Final == evaluator.DecisionDeny {
			decision = fmt.Sprintf("DENY at Layer %d", res.DeniedAtLayer)
		}
		fmt.Fprintf(r.w, "  %-25s %-20s %-22s %s\n",
			truncate(res.PrincipalName, 24),
			truncate(res.Action, 19),
			truncate(res.BucketName, 21),
			decision,
		)
	}
	fmt.Fprintln(r.w)
}

func (r *Reporter) header(title string) {
	fmt.Fprintln(r.w)
	fmt.Fprintln(r.w, title)
	fmt.Fprintln(r.w, strings.Repeat("=", sectionWidth))
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
