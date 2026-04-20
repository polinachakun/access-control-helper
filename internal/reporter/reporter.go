// Package reporter formats the Alloy model checker results into a
// readable access analysis report.
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
	Principal          string
	Bucket             string
	Action             string
	Decision           string
	DeniedAtDesc       string
	AdditionalFindings []string
	Layers             [7]LayerInfo
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
		// "granting" layers (4, 5) show "NOT GRANTED" on failure (they don't
		// block, they just didn't grant). "blocking" layers show "DENY".
		for i, suffix := range layerSuffixes {
			tr.Layers[i] = LayerInfo{Name: layerNames[i]}
			cr, ok := byName[key.AssertionBaseName+suffix]
			if ok && cr.Valid {
				tr.Layers[i].Status = "PASS"
			} else if generator.LayerPredicates[i].Kind == "granting" {
				tr.Layers[i].Status = "NOT GRANTED"
			} else {
				tr.Layers[i].Status = "DENY"
			}
		}

		if tr.Decision == "DENY" {
			tr.DeniedAtDesc, tr.AdditionalFindings = deniedAtDescription(tr.Layers)
		}

		results = append(results, tr)
	}
	return results
}

func deniedAtDescription(layers [7]LayerInfo) (string, []string) {
	var additional []string

	l4ng := layers[3].Status == "NOT GRANTED"
	l5ng := layers[4].Status == "NOT GRANTED"

	// blocking layers first
	for _, idx := range []int{0, 1, 2, 5, 6} {
		if layers[idx].Status == "DENY" {
			if l4ng && l5ng {
				additional = append(additional, "No grant from Layer 4/5")
			}
			return fmt.Sprintf("Layer %d", idx+1), additional
		}
	}

	if l4ng && l5ng {
		return "Layer 4/5", nil
	}
	if l5ng {
		return "Layer 5", nil
	}
	if l4ng {
		return "Layer 4", nil
	}

	return "unknown", nil
}

type Reporter struct {
	w io.Writer
}

func New(w io.Writer) *Reporter { return &Reporter{w: w} }

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
		res.Principal, generator.HumanAction(res.Action), res.Bucket)
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
		for _, finding := range res.AdditionalFindings {
			fmt.Fprintf(r.w, "  Additional finding: %s\n", finding)
		}
	}
	fmt.Fprintln(r.w)
}

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
			truncate(generator.HumanAction(res.Action), 19),
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
