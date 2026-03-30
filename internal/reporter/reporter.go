// Package reporter formats the Alloy model checker results into a
// human-readable access analysis report with per-layer breakdown.
package reporter

import (
	"fmt"
	"io"
	"strings"

	"access-control-helper/internal/analyzer"
	"access-control-helper/internal/generator"
)

const (
	sectionWidth = 62
	colHeader    = 38 // width of the "Layer N — Name:" column
)

// LayerInfo holds the status of a single evaluation layer for one triple.
type LayerInfo struct {
	Name   string // e.g. "Explicit Deny"
	Status string // "PASS" or "DENY"
}

// TripleResult holds the Alloy-derived access decision for one (principal, bucket, action) triple.
type TripleResult struct {
	Principal    string
	Bucket       string
	Action       string
	Decision     string // "ALLOW" or "DENY"
	DeniedAtDesc string // e.g. "Layer 1" or "Layer 4/5" or "" if allowed
	Layers       [7]LayerInfo
}

var layerNames = [7]string{
	"Explicit Deny",
	"RCP (Resource Control Policy)",
	"SCP (Service Control Policy)",
	"Resource Policy (Bucket Policy)",
	"Identity Policy",
	"Permission Boundary",
	"Session Policy",
}

var layerSuffixes = [7]string{"_L1", "_L2", "_L3", "_L4", "_L5", "_L6", "_L7"}

// BuildTripleResults converts Alloy CheckResults into TripleResults using the
// TripleKey mapping from the generator.
func BuildTripleResults(checks []analyzer.CheckResult, keys []generator.TripleKey) []*TripleResult {
	// Index check results by assertion name.
	byName := make(map[string]analyzer.CheckResult, len(checks))
	for _, cr := range checks {
		byName[cr.Name] = cr
	}

	var results []*TripleResult
	for _, key := range keys {
		tr := &TripleResult{
			Principal: key.Role,
			Bucket:    key.Bucket,
			Action:    key.Action,
		}

		// Combined assertion: UNSAT → ALLOW, SAT → DENY.
		combined, ok := byName[key.AssertionBaseName]
		if ok && combined.Valid {
			tr.Decision = "ALLOW"
		} else {
			tr.Decision = "DENY"
		}

		// Per-layer status.
		// Layers 4 and 5 are OR-ed grant layers: a failing assertion means
		// "this path didn't grant access", not an explicit denial. All other
		// layers are blocking layers where failure means an actual deny.
		for i, suffix := range layerSuffixes {
			tr.Layers[i] = LayerInfo{Name: layerNames[i]}
			cr, ok := byName[key.AssertionBaseName+suffix]
			if ok && cr.Valid {
				tr.Layers[i].Status = "PASS"
			} else if i == 3 || i == 4 { // L4 (index 3) and L5 (index 4)
				tr.Layers[i].Status = "NOT GRANTED"
			} else {
				tr.Layers[i].Status = "DENY"
			}
		}

		// Determine which layer denied (first DENY scanning L1→L7).
		if tr.Decision == "DENY" {
			tr.DeniedAtDesc = deniedAtDescription(tr.Layers)
		}

		results = append(results, tr)
	}
	return results
}

// deniedAtDescription returns a human-readable description of where access was denied.
func deniedAtDescription(layers [7]LayerInfo) string {
	// Layers 1-3: blocking layers — first DENY wins.
	for i := 0; i < 3; i++ {
		if layers[i].Status == "DENY" {
			return fmt.Sprintf("Layer %d", i+1)
		}
	}
	// Layers 4+5: OR-ed grant layers — both must fail to deny.
	if layers[3].Status == "NOT GRANTED" && layers[4].Status == "NOT GRANTED" {
		return "Layer 4/5"
	}
	// Layers 6-7: blocking layers.
	for i := 5; i < 7; i++ {
		if layers[i].Status == "DENY" {
			return fmt.Sprintf("Layer %d", i+1)
		}
	}
	return "unknown"
}

// Reporter writes analysis results to an io.Writer.
type Reporter struct {
	w io.Writer
}

// New creates a Reporter that writes to w.
func New(w io.Writer) *Reporter { return &Reporter{w: w} }

// Report writes the full analysis: per-triple layer breakdown.
func (r *Reporter) Report(results []*TripleResult) {
	r.header("Access Analysis Report")

	if len(results) == 0 {
		fmt.Fprintln(r.w, "No (principal, bucket, action) triples found — nothing to analyse.")
		return
	}

	for _, res := range results {
		r.reportTriple(res)
	}
}

var layerLabels = [7]string{
	"Layer 1 — Deny Evaluation",
	"Layer 2 — RCP",
	"Layer 3 — SCP",
	"Layer 4 — Resource Policy",
	"Layer 5 — Identity Policy",
	"Layer 6 — Permission Boundary",
	"Layer 7 — Session Policy",
}

func (r *Reporter) reportTriple(res *TripleResult) {
	fmt.Fprintf(r.w, "\nQuery: can %q perform %s on %q?\n",
		res.Principal, res.Action, res.Bucket)
	fmt.Fprintln(r.w, strings.Repeat("─", sectionWidth))

	for i, layer := range res.Layers {
		label := layerLabels[i] + ":"
		fmt.Fprintf(r.w, "  %-*s %s\n", colHeader, label, layer.Status)
	}

	fmt.Fprintln(r.w)
	if res.Decision == "ALLOW" {
		fmt.Fprintln(r.w, "  Result: ALLOW")
	} else {
		fmt.Fprintf(r.w, "  Result: DENY at %s\n", res.DeniedAtDesc)
	}
	fmt.Fprintln(r.w)
}

// Summary prints a compact summary table.
func (r *Reporter) Summary(results []*TripleResult) {
	if len(results) == 0 {
		return
	}

	r.header("Access Summary")
	fmt.Fprintf(r.w, "  %-25s %-20s %-22s %s\n", "Principal", "Action", "Bucket", "Decision")
	fmt.Fprintf(r.w, "  %s %s %s %s\n",
		strings.Repeat("─", 25), strings.Repeat("─", 20),
		strings.Repeat("─", 22), strings.Repeat("─", 20))

	for _, res := range results {
		decision := res.Decision
		if res.Decision == "DENY" {
			decision = "DENY at " + res.DeniedAtDesc
		}
		fmt.Fprintf(r.w, "  %-25s %-20s %-22s %s\n",
			truncate(res.Principal, 24),
			truncate(res.Action, 19),
			truncate(res.Bucket, 21),
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
