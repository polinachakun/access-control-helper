package resolver

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

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
