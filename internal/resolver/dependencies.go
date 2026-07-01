package resolver

import (
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2"

	"access-control-helper/internal/parser"
)

func usesDataSource(raw *parser.RawResource) bool {
	for _, expr := range raw.Attributes {
		for _, traversal := range expr.Variables() {
			if len(traversal) >= 1 {
				if root, ok := traversal[0].(hcl.TraverseRoot); ok && root.Name == "data" {
					return true
				}
			}
		}
	}
	for _, blocks := range raw.Blocks {
		for _, block := range blocks {
			if blockUsesDataSource(block) {
				return true
			}
		}
	}
	return false
}

func blockUsesDataSource(block parser.RawBlock) bool {
	for _, expr := range block.Attributes {
		for _, traversal := range expr.Variables() {
			if len(traversal) >= 1 {
				if root, ok := traversal[0].(hcl.TraverseRoot); ok && root.Name == "data" {
					return true
				}
			}
		}
	}
	for _, children := range block.Blocks {
		for _, child := range children {
			if blockUsesDataSource(child) {
				return true
			}
		}
	}
	return false
}

// collectVarRefs returns the set of all var.<name> references found in the given resources.
func collectVarRefs(resources []parser.RawResource, dataSources []parser.RawResource) map[string]bool {
	names := make(map[string]bool)
	for _, raw := range append(resources, dataSources...) {
		for _, expr := range raw.Attributes {
			addVarRefsFromExpr(expr, names)
		}
		for _, blocks := range raw.Blocks {
			for _, block := range blocks {
				addVarRefsFromBlock(block, names)
			}
		}
	}
	return names
}

func addVarRefsFromExpr(expr hcl.Expression, names map[string]bool) {
	for _, traversal := range expr.Variables() {
		if len(traversal) < 2 {
			continue
		}
		root, ok := traversal[0].(hcl.TraverseRoot)
		if !ok || root.Name != "var" {
			continue
		}
		if attr, ok := traversal[1].(hcl.TraverseAttr); ok {
			names[attr.Name] = true
		}
	}
}

func addVarRefsFromBlock(block parser.RawBlock, names map[string]bool) {
	for _, expr := range block.Attributes {
		addVarRefsFromExpr(expr, names)
	}
	for _, children := range block.Blocks {
		for _, child := range children {
			addVarRefsFromBlock(child, names)
		}
	}
}

// extractDependencies finds all resource references in a raw resource.
func (r *Resolver) extractDependencies(raw *parser.RawResource) []string {
	var deps []string
	seen := make(map[string]bool)
	selfRef := raw.GetResourceRef()

	for _, expr := range raw.Attributes {
		refs := extractRefsFromExpr(expr)
		for _, ref := range refs {
			if !seen[ref] && ref != selfRef {
				seen[ref] = true
				deps = append(deps, ref)
			}
		}
	}

	for _, blocks := range raw.Blocks {
		for _, block := range blocks {
			collectRefsFromRawBlock(block, seen, &deps, selfRef)
		}
	}

	return deps
}

func collectRefsFromRawBlock(block parser.RawBlock, seen map[string]bool, deps *[]string, selfRef string) {
	for _, expr := range block.Attributes {
		for _, ref := range extractRefsFromExpr(expr) {
			if !seen[ref] && ref != selfRef {
				seen[ref] = true
				*deps = append(*deps, ref)
			}
		}
	}
	for _, children := range block.Blocks {
		for _, child := range children {
			collectRefsFromRawBlock(child, seen, deps, selfRef)
		}
	}
}

// extractRefsFromExpr extracts resource references from an expression.
func extractRefsFromExpr(expr hcl.Expression) []string {
	if expr == nil {
		return nil
	}

	vars := expr.Variables()
	var refs []string
	seen := make(map[string]bool)

	for _, traversal := range vars {
		ref := traversalToRef(traversal)
		if ref != "" && !seen[ref] {
			seen[ref] = true
			refs = append(refs, ref)
		}
	}

	return refs
}

// traversalToRef converts an HCL traversal to a resource reference.
func traversalToRef(traversal hcl.Traversal) string {
	if len(traversal) < 2 {
		return ""
	}

	root, ok := traversal[0].(hcl.TraverseRoot)
	if !ok {
		return ""
	}

	// Skip non-resource references
	if root.Name == "local" || root.Name == "var" || root.Name == "data" ||
		root.Name == "module" || root.Name == "path" || root.Name == "terraform" {
		return ""
	}

	if !strings.HasPrefix(root.Name, "aws_") {
		return ""
	}

	attr, ok := traversal[1].(hcl.TraverseAttr)
	if !ok {
		return ""
	}

	return root.Name + "." + attr.Name
}

func ExtractResourceRefFromString(s string) string {
	// Match Terraform interpolation syntax
	re := regexp.MustCompile(`\$\{(aws_[a-z0-9_]+)\.([a-z0-9_]+)`)
	matches := re.FindStringSubmatch(s)
	if len(matches) >= 3 {
		return matches[1] + "." + matches[2]
	}

	re = regexp.MustCompile(`^(aws_[a-z0-9_]+)\.([a-z0-9_]+)`)
	matches = re.FindStringSubmatch(s)
	if len(matches) >= 3 {
		return matches[1] + "." + matches[2]
	}

	return ""
}
