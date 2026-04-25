// Package preflight provides lightweight syntax checks that run before the
// main pipeline. These checks catch structural problems early — before the
// HCL parser, IR builder, or Alloy are invoked.
//
// Responsibility split:
//
//	preflight  → Terraform HCL syntax (terraform fmt)
//	parser     → HCL AST construction
//	ir/builder → policy JSON syntax (ParsePolicyDocument)
//	analyzer   → access-control semantics (Alloy)
package preflight

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// TerraformResult reports what the pre-flight Terraform check found.
type TerraformResult struct {
	Available bool
	Passed    bool
	Output    string
}

func CheckTerraform(path string, stderr io.Writer) TerraformResult {
	tfPath, err := exec.LookPath("terraform")
	if err != nil {
		fmt.Fprintln(stderr, "note: terraform not found in PATH; skipping HCL syntax pre-check")
		return TerraformResult{Available: false, Passed: true}
	}

	cmd := exec.Command(tfPath, "fmt", "-check", "-recursive", path)
	out, err := cmd.CombinedOutput()

	result := TerraformResult{Available: true}
	if err != nil {
		result.Passed = false
		result.Output = strings.TrimSpace(string(out))
	} else {
		result.Passed = true
	}
	return result
}
