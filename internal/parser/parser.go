// Package parser provides HCL parsing for Terraform files.
package parser

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"
)

// ParseResult holds the results of parsing Terraform files.
type ParseResult struct {
	Resources []RawResource
	Locals    map[string]hcl.Expression
	Variables map[string]hcl.Expression
	Files     map[string]*hcl.File
	Diags     hcl.Diagnostics
}

// RawResource represents a parsed but unresolved Terraform resource.
type RawResource struct {
	Type       string
	Name       string
	Attributes map[string]hcl.Expression
	Blocks     map[string][]RawBlock
	Range      hcl.Range
}

// RawBlock represents a nested block within a resource.
type RawBlock struct {
	Type       string
	Labels     []string
	Attributes map[string]hcl.Expression
	Blocks     map[string][]RawBlock
}

// Parser wraps the HCL parser with Terraform-specific functionality.
type Parser struct {
	hclParser *hclparse.Parser
}

// NewParser creates a new Parser instance.
func NewParser() *Parser {
	return &Parser{
		hclParser: hclparse.NewParser(),
	}
}

// ParseFile parses a single Terraform file.
func (p *Parser) ParseFile(path string) (*ParseResult, error) {
	return p.ParseFiles([]string{path})
}

// ParseDirectory parses all .tf files in a directory.
func (p *Parser) ParseDirectory(dir string) (*ParseResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", dir, err)
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".tf" {
			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no .tf files found in %s", dir)
	}

	return p.ParseFiles(files)
}

// ParseFiles parses multiple Terraform files and merges the results.
func (p *Parser) ParseFiles(paths []string) (*ParseResult, error) {
	result := &ParseResult{
		Locals:    make(map[string]hcl.Expression),
		Variables: make(map[string]hcl.Expression),
		Files:     make(map[string]*hcl.File),
	}

	for _, path := range paths {
		file, diags := p.hclParser.ParseHCLFile(path)
		result.Diags = append(result.Diags, diags...)
		if file == nil {
			continue
		}
		result.Files[path] = file

		if err := p.extractFromFile(file, result); err != nil {
			return nil, fmt.Errorf("failed to extract from %s: %w", path, err)
		}
	}

	if result.Diags.HasErrors() {
		return result, fmt.Errorf("parse errors: %s", result.Diags.Error())
	}

	return result, nil
}

// extractFromFile extracts resources, locals, and variables from a parsed file.
func (p *Parser) extractFromFile(file *hcl.File, result *ParseResult) error {
	content, _, diags := file.Body.PartialContent(TopLevelSchema)
	result.Diags = append(result.Diags, diags...)

	for _, block := range content.Blocks {
		switch block.Type {
		case "resource":
			if len(block.Labels) != 2 {
				continue
			}
			resourceType := block.Labels[0]
			resourceName := block.Labels[1]

			if !IsSupportedResourceType(resourceType) {
				continue
			}

			raw, err := p.extractResource(resourceType, resourceName, block.Body, block.DefRange)
			if err != nil {
				return err
			}
			result.Resources = append(result.Resources, raw)

		case "locals":
			p.extractLocals(block.Body, result)

		case "variable":
			if len(block.Labels) == 1 {
				p.extractVariable(block.Labels[0], block.Body, result)
			}
		}
	}

	return nil
}

// extractResource extracts a resource block into a RawResource.
func (p *Parser) extractResource(resourceType, name string, body hcl.Body, defRange hcl.Range) (RawResource, error) {
	schema := ResourceSchema(resourceType)

	content, remain, diags := body.PartialContent(schema)
	if diags.HasErrors() {
		return RawResource{}, fmt.Errorf("schema error for %s.%s: %s", resourceType, name, diags.Error())
	}

	raw := RawResource{
		Type:       resourceType,
		Name:       name,
		Attributes: make(map[string]hcl.Expression),
		Blocks:     make(map[string][]RawBlock),
		Range:      defRange,
	}

	// Extract defined attributes
	for attrName, attr := range content.Attributes {
		raw.Attributes[attrName] = attr.Expr
	}

	// Extract any remaining attributes (dynamic attributes not in schema)
	remainAttrs, _ := remain.JustAttributes()
	for attrName, attr := range remainAttrs {
		raw.Attributes[attrName] = attr.Expr
	}

	// Extract nested blocks
	for _, block := range content.Blocks {
		rawBlock := p.extractBlock(block)
		raw.Blocks[block.Type] = append(raw.Blocks[block.Type], rawBlock)
	}

	return raw, nil
}

// extractBlock extracts a nested block.
func (p *Parser) extractBlock(block *hcl.Block) RawBlock {
	rawBlock := RawBlock{
		Type:       block.Type,
		Labels:     block.Labels,
		Attributes: make(map[string]hcl.Expression),
		Blocks:     make(map[string][]RawBlock),
	}

	attrs, _ := block.Body.JustAttributes()
	for attrName, attr := range attrs {
		rawBlock.Attributes[attrName] = attr.Expr
	}

	// TODO: For deeply nested blocks, it needed recursive handling

	return rawBlock
}

// extractLocals extracts local values from a locals block.
func (p *Parser) extractLocals(body hcl.Body, result *ParseResult) {
	attrs, _ := body.JustAttributes()
	for name, attr := range attrs {
		result.Locals[name] = attr.Expr
	}
}

// extractVariable extracts a variable definition.
func (p *Parser) extractVariable(name string, body hcl.Body, result *ParseResult) {
	attrs, _ := body.JustAttributes()
	if defaultAttr, ok := attrs["default"]; ok {
		result.Variables[name] = defaultAttr.Expr
	}
}

// GetResourceRef returns the full Terraform resource reference.
func (r *RawResource) GetResourceRef() string {
	return fmt.Sprintf("%s.%s", r.Type, r.Name)
}

// EvalContext creates an HCL evaluation context for resolving expressions.
// Note: This is a simplified context; full resolution is handled by the resolver package.
func (p *Parser) EvalContext(result *ParseResult) *hcl.EvalContext {
	ctx := &hcl.EvalContext{
		Variables: make(map[string]cty.Value),
	}

	for _, expr := range result.Locals {
		_, _ = expr.Value(nil)
	}

	return ctx
}

// ExpressionToString attempts to evaluate an expression to a string.
// Returns empty string if not evaluable.
func ExpressionToString(expr hcl.Expression, ctx *hcl.EvalContext) string {
	if expr == nil {
		return ""
	}

	val, diags := expr.Value(ctx)
	if diags.HasErrors() || val.IsNull() || !val.IsKnown() {
		return ""
	}

	if val.Type() == cty.String {
		return val.AsString()
	}

	return ""
}

// ExpressionToStringMap attempts to evaluate an expression to a string map.
func ExpressionToStringMap(expr hcl.Expression, ctx *hcl.EvalContext) map[string]string {
	if expr == nil {
		return nil
	}

	val, diags := expr.Value(ctx)
	if diags.HasErrors() || val.IsNull() || !val.IsKnown() {
		return nil
	}

	if !val.Type().IsObjectType() && !val.Type().IsMapType() {
		return nil
	}

	result := make(map[string]string)
	for it := val.ElementIterator(); it.Next(); {
		key, v := it.Element()
		if key.Type() == cty.String && v.Type() == cty.String {
			result[key.AsString()] = v.AsString()
		}
	}

	return result
}

// GetExpressionAsLiteral extracts a literal string from an expression.
func GetExpressionAsLiteral(expr hcl.Expression) (string, bool) {
	if expr == nil {
		return "", false
	}

	val, diags := expr.Value(nil)
	if !diags.HasErrors() && val.Type() == cty.String {
		return val.AsString(), true
	}

	return "", false
}

// GetResourceReferences extracts resource references from an expression.
func GetResourceReferences(expr hcl.Expression) []string {
	if expr == nil {
		return nil
	}

	vars := expr.Variables()
	var refs []string
	seen := make(map[string]bool)

	for _, traversal := range vars {
		ref := traversalToResourceRef(traversal)
		if ref != "" && !seen[ref] {
			seen[ref] = true
			refs = append(refs, ref)
		}
	}

	return refs
}

// traversalToResourceRef converts an HCL traversal to a resource reference.
func traversalToResourceRef(traversal hcl.Traversal) string {
	if len(traversal) < 2 {
		return ""
	}

	// First element should be resource type
	root, ok := traversal[0].(hcl.TraverseRoot)
	if !ok {
		return ""
	}

	// Check if it's a known resource type prefix
	if !isResourceTypePrefix(root.Name) {
		return ""
	}

	// Second element should be resource name
	attr, ok := traversal[1].(hcl.TraverseAttr)
	if !ok {
		return ""
	}

	return root.Name + "." + attr.Name
}

// isResourceTypePrefix checks if a name could be a resource type.
func isResourceTypePrefix(name string) bool {
	prefixes := []string{"aws_", "data", "local", "var", "module"}
	for _, prefix := range prefixes {
		if name == prefix || (len(name) > len(prefix) && name[:len(prefix)] == prefix[:len(prefix)]) {
			return true
		}
	}
	return IsSupportedResourceType(name)
}
