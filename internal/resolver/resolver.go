package resolver

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"

	"access-control-helper/internal/parser"
)

// ResolvedResource represents a resource with resolved attribute values.
type ResolvedResource struct {
	Type       string
	Name       string
	Attributes map[string]interface{}
	Blocks     map[string][]ResolvedBlock
	References []string // Resource references found in this resource
}

// ResolvedBlock represents a resolved nested block.
type ResolvedBlock struct {
	Type       string
	Labels     []string
	Attributes map[string]interface{}
	Blocks     map[string][]ResolvedBlock
}

// Resolver handles reference resolution and value evaluation.
type Resolver struct {
	graph     *DependencyGraph
	resources map[string]*ResolvedResource
	locals    map[string]cty.Value
	evalCtx   *hcl.EvalContext
	warnings  []string
}

// NewResolver creates a new Resolver.
func NewResolver() *Resolver {
	return &Resolver{
		graph:     NewDependencyGraph(),
		resources: make(map[string]*ResolvedResource),
		locals:    make(map[string]cty.Value),
	}
}

// Warnings returns non-fatal warnings collected during resolution.
func (r *Resolver) Warnings() []string { return r.warnings }

// Resolve processes parsed resources and resolves references.
func (r *Resolver) Resolve(parseResult *parser.ParseResult) (map[string]*ResolvedResource, error) {
	r.evalCtx = r.buildEvalContext(parseResult)

	// First pass: evaluate locals
	for name, expr := range parseResult.Locals {
		val, diags := expr.Value(r.evalCtx)
		if !diags.HasErrors() {
			r.locals[name] = val
		}
	}

	r.updateLocalsInContext()

	// Synthesize data "aws_iam_policy_document" sources into the eval context so
	// that resource attributes referencing data.aws_iam_policy_document.X.json
	// are resolved to a real JSON string rather than an unresolved reference.
	r.synthesizeDataSources(parseResult)

	// Second pass: add all resources to the graph
	for _, raw := range parseResult.Resources {
		ref := raw.GetResourceRef()
		r.graph.AddNode(ref, raw.Type, raw.Name)
	}

	// Third pass: build dependency edges
	for _, raw := range parseResult.Resources {
		ref := raw.GetResourceRef()
		deps := r.extractDependencies(&raw)
		for _, dep := range deps {
			r.graph.AddEdge(ref, dep)
		}
	}

	// Fourth pass: resolve in topological order
	order, err := r.graph.TopologicalSort()
	if err != nil {
		return nil, fmt.Errorf("dependency resolution failed: %w", err)
	}

	rawMap := make(map[string]*parser.RawResource)
	for i := range parseResult.Resources {
		raw := &parseResult.Resources[i]
		rawMap[raw.GetResourceRef()] = raw
	}

	for _, ref := range order {
		raw := rawMap[ref]
		if raw == nil {
			continue
		}

		resolved, err := r.resolveResource(raw)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve %s: %w", ref, err)
		}
		r.resources[ref] = resolved

		r.updateResourceInContext(resolved)
	}

	r.synthesizeDataSources(parseResult)
	for _, ref := range order {
		raw := rawMap[ref]
		if raw == nil || !usesDataSource(raw) {
			continue
		}
		resolved, err := r.resolveResource(raw)
		if err != nil {
			continue
		}
		r.resources[ref] = resolved
		r.updateResourceInContext(resolved)
	}

	return r.resources, nil
}

// GetGraph returns the dependency graph.
func (r *Resolver) GetGraph() *DependencyGraph {
	return r.graph
}

// buildEvalContext creates the initial HCL evaluation context.
func (r *Resolver) buildEvalContext(parseResult *parser.ParseResult) *hcl.EvalContext {
	ctx := &hcl.EvalContext{
		Variables: make(map[string]cty.Value),
		Functions: make(map[string]function.Function),
	}

	ctx.Functions["jsonencode"] = stdlib.JSONEncodeFunc
	ctx.Functions["jsondecode"] = stdlib.JSONDecodeFunc
	ctx.Functions["lower"] = stdlib.LowerFunc
	ctx.Functions["upper"] = stdlib.UpperFunc
	ctx.Functions["replace"] = stdlib.ReplaceFunc
	ctx.Functions["format"] = stdlib.FormatFunc
	ctx.Functions["join"] = createJoinFunc()
	ctx.Functions["split"] = stdlib.SplitFunc
	ctx.Functions["length"] = stdlib.LengthFunc
	ctx.Functions["coalesce"] = stdlib.CoalesceFunc
	ctx.Functions["concat"] = stdlib.ConcatFunc
	ctx.Functions["contains"] = stdlib.ContainsFunc
	ctx.Functions["lookup"] = createLookupFunc()
	ctx.Functions["tostring"] = createToStringFunc()
	ctx.Functions["tolist"] = createToListFunc()
	ctx.Functions["toset"] = createToSetFunc()
	ctx.Functions["tomap"] = createToMapFunc()

	ctx.Variables["local"] = cty.EmptyObjectVal
	ctx.Variables["var"] = cty.EmptyObjectVal

	varVals := make(map[string]cty.Value)
	for name, expr := range parseResult.Variables {
		val, diags := expr.Value(nil)
		if !diags.HasErrors() {
			varVals[name] = val
		}
	}

	for name := range collectVarRefs(parseResult.Resources, parseResult.DataSources) {
		if _, ok := varVals[name]; !ok {
			varVals[name] = cty.StringVal("")
		}
	}

	if len(varVals) > 0 {
		ctx.Variables["var"] = cty.ObjectVal(varVals)
	}

	return ctx
}

// updateLocalsInContext updates the eval context with resolved locals.
func (r *Resolver) updateLocalsInContext() {
	if len(r.locals) > 0 {
		r.evalCtx.Variables["local"] = cty.ObjectVal(r.locals)
	}
}

// updateResourceInContext adds a resolved resource to the eval context.
func (r *Resolver) updateResourceInContext(res *ResolvedResource) {
	attrs := make(map[string]cty.Value)

	for name, val := range res.Attributes {
		attrs[name] = interfaceToCty(val)
	}

	if _, ok := attrs["id"]; !ok {
		attrs["id"] = cty.StringVal(res.Name)
	}
	if _, ok := attrs["arn"]; !ok {
		attrs["arn"] = cty.StringVal(arnPlaceholder(res.Type, res.Name))
	}

	resourceVal := cty.ObjectVal(attrs)

	typeKey := res.Type
	existing := r.evalCtx.Variables[typeKey]
	var typeVals map[string]cty.Value

	if existing.IsNull() || existing == cty.NilVal {
		typeVals = make(map[string]cty.Value)
	} else if existing.Type().IsObjectType() {
		typeVals = make(map[string]cty.Value)
		for it := existing.ElementIterator(); it.Next(); {
			key, val := it.Element()
			typeVals[key.AsString()] = val
		}
	} else {
		typeVals = make(map[string]cty.Value)
	}

	typeVals[res.Name] = resourceVal
	r.evalCtx.Variables[typeKey] = cty.ObjectVal(typeVals)
}

// resolveResource resolves a single resource's attributes.
func (r *Resolver) resolveResource(raw *parser.RawResource) (*ResolvedResource, error) {
	resolved := &ResolvedResource{
		Type:       raw.Type,
		Name:       raw.Name,
		Attributes: make(map[string]interface{}),
		Blocks:     make(map[string][]ResolvedBlock),
	}

	for name, expr := range raw.Attributes {
		resolved.Attributes[name] = r.resolveExpression(expr)
		resolved.References = append(resolved.References, extractRefsFromExpr(expr)...)
	}

	for blockType, blocks := range raw.Blocks {
		for _, block := range blocks {
			resolved.Blocks[blockType] = append(resolved.Blocks[blockType], r.resolveBlock(block))
		}
	}

	return resolved, nil
}

func (r *Resolver) resolveBlock(raw parser.RawBlock) ResolvedBlock {
	resolved := ResolvedBlock{
		Type:       raw.Type,
		Labels:     raw.Labels,
		Attributes: make(map[string]interface{}),
		Blocks:     make(map[string][]ResolvedBlock),
	}
	for name, expr := range raw.Attributes {
		resolved.Attributes[name] = r.resolveExpression(expr)
	}
	for blockType, children := range raw.Blocks {
		for _, child := range children {
			resolved.Blocks[blockType] = append(resolved.Blocks[blockType], r.resolveBlock(child))
		}
	}
	return resolved
}

// resolveExpression evaluates an HCL expression to a Go value.
func (r *Resolver) resolveExpression(expr hcl.Expression) interface{} {
	if expr == nil {
		return nil
	}

	// Check if it's a jsonencode call
	if call, diags := hcl.ExprCall(expr); !diags.HasErrors() && call != nil {
		if call.Name == "jsonencode" && len(call.Arguments) > 0 {
			val, diags := call.Arguments[0].Value(r.evalCtx)
			if !diags.HasErrors() {
				jsonBytes, err := ctyToJSON(val)
				if err == nil {
					return string(jsonBytes)
				}
			}
		}
	}

	val, diags := expr.Value(r.evalCtx)
	if diags.HasErrors() {
		return exprToString(expr)
	}

	return ctyToInterface(val)
}
