package resolver

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

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
}

// NewResolver creates a new Resolver.
func NewResolver() *Resolver {
	return &Resolver{
		graph:     NewDependencyGraph(),
		resources: make(map[string]*ResolvedResource),
		locals:    make(map[string]cty.Value),
	}
}

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
	ctx.Functions["join"] = stdlib.JoinFunc
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
		attrs["arn"] = cty.StringVal(fmt.Sprintf("arn:aws::::%s", res.Name))
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

// exprToString extracts the source text of an expression.
func exprToString(expr hcl.Expression) string {
	vars := expr.Variables()
	if len(vars) > 0 {
		var parts []string
		for _, v := range vars {
			parts = append(parts, formatTraversal(v))
		}
		return strings.Join(parts, ", ")
	}
	return ""
}

// formatTraversal converts a traversal to a string representation.
func formatTraversal(traversal hcl.Traversal) string {
	var parts []string
	for _, step := range traversal {
		switch t := step.(type) {
		case hcl.TraverseRoot:
			parts = append(parts, t.Name)
		case hcl.TraverseAttr:
			parts = append(parts, t.Name)
		case hcl.TraverseIndex:
			parts = append(parts, "[...]")
		}
	}
	return strings.Join(parts, ".")
}

// ctyToInterface converts a cty.Value to a Go interface{}.
func ctyToInterface(val cty.Value) interface{} {
	if val.IsNull() || !val.IsKnown() {
		return nil
	}

	switch {
	case val.Type() == cty.String:
		return val.AsString()
	case val.Type() == cty.Number:
		bf := val.AsBigFloat()
		if bf.IsInt() {
			i, _ := bf.Int64()
			return i
		}
		f, _ := bf.Float64()
		return f
	case val.Type() == cty.Bool:
		return val.True()
	case val.Type().IsListType() || val.Type().IsTupleType() || val.Type().IsSetType():
		var items []interface{}
		for it := val.ElementIterator(); it.Next(); {
			_, v := it.Element()
			items = append(items, ctyToInterface(v))
		}
		return items
	case val.Type().IsMapType() || val.Type().IsObjectType():
		m := make(map[string]interface{})
		for it := val.ElementIterator(); it.Next(); {
			k, v := it.Element()
			if k.Type() == cty.String {
				m[k.AsString()] = ctyToInterface(v)
			}
		}
		return m
	default:
		return nil
	}
}

// interfaceToCty converts a Go interface{} to a cty.Value.
func interfaceToCty(val interface{}) cty.Value {
	if val == nil {
		return cty.NullVal(cty.DynamicPseudoType)
	}

	switch v := val.(type) {
	case string:
		return cty.StringVal(v)
	case int:
		return cty.NumberIntVal(int64(v))
	case int64:
		return cty.NumberIntVal(v)
	case float64:
		return cty.NumberFloatVal(v)
	case bool:
		return cty.BoolVal(v)
	case []interface{}:
		if len(v) == 0 {
			return cty.ListValEmpty(cty.DynamicPseudoType)
		}
		vals := make([]cty.Value, len(v))
		for i, item := range v {
			vals[i] = interfaceToCty(item)
		}
		return cty.TupleVal(vals)
	case map[string]interface{}:
		if len(v) == 0 {
			return cty.EmptyObjectVal
		}
		vals := make(map[string]cty.Value)
		for k, item := range v {
			vals[k] = interfaceToCty(item)
		}
		return cty.ObjectVal(vals)
	default:
		return cty.StringVal(fmt.Sprintf("%v", v))
	}
}

// ctyToJSON converts a cty.Value to JSON bytes.
func ctyToJSON(val cty.Value) ([]byte, error) {
	goVal := ctyToInterface(val)
	return json.Marshal(goVal)
}

func createLookupFunc() function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "map", Type: cty.DynamicPseudoType},
			{Name: "key", Type: cty.String},
		},
		VarParam: &function.Parameter{Name: "default", Type: cty.DynamicPseudoType},
		Type:     function.StaticReturnType(cty.DynamicPseudoType),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			mapVal := args[0]
			keyVal := args[1]

			if !mapVal.Type().IsObjectType() && !mapVal.Type().IsMapType() {
				if len(args) > 2 {
					return args[2], nil
				}
				return cty.NullVal(cty.DynamicPseudoType), nil
			}

			key := keyVal.AsString()
			if mapVal.Type().HasAttribute(key) {
				return mapVal.GetAttr(key), nil
			}

			if len(args) > 2 {
				return args[2], nil
			}
			return cty.NullVal(cty.DynamicPseudoType), nil
		},
	})
}

func createToStringFunc() function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "value", Type: cty.DynamicPseudoType},
		},
		Type: function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			val := args[0]
			if val.Type() == cty.String {
				return val, nil
			}
			return cty.StringVal(fmt.Sprintf("%v", ctyToInterface(val))), nil
		},
	})
}

func createToListFunc() function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "value", Type: cty.DynamicPseudoType},
		},
		Type: function.StaticReturnType(cty.List(cty.DynamicPseudoType)),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			return args[0], nil
		},
	})
}

func createToSetFunc() function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "value", Type: cty.DynamicPseudoType},
		},
		Type: function.StaticReturnType(cty.Set(cty.DynamicPseudoType)),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			return args[0], nil
		},
	})
}

func createToMapFunc() function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "value", Type: cty.DynamicPseudoType},
		},
		Type: function.StaticReturnType(cty.Map(cty.DynamicPseudoType)),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			return args[0], nil
		},
	})
}

// ExtractResourceRefFromString extracts a resource reference from a string.
// E.g., "${aws_s3_bucket.my_bucket.id}" -> "aws_s3_bucket.my_bucket"
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
