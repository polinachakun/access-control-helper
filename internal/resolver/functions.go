package resolver

import (
	"fmt"
	"strings"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

func createJoinFunc() function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "separator", Type: cty.String},
		},
		VarParam: &function.Parameter{
			Name: "lists",
			Type: cty.DynamicPseudoType,
		},
		Type: function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			if len(args) == 0 {
				return cty.StringVal(""), nil
			}
			sep := args[0].AsString()
			var items []string
			for _, listVal := range args[1:] {
				if listVal.IsNull() || !listVal.IsKnown() {
					continue
				}
				t := listVal.Type()
				switch {
				case t.IsListType() || t.IsTupleType() || t.IsSetType():
					for it := listVal.ElementIterator(); it.Next(); {
						_, v := it.Element()
						if v.IsNull() || !v.IsKnown() {
							continue
						}
						if v.Type() == cty.String {
							items = append(items, v.AsString())
						} else {
							items = append(items, fmt.Sprintf("%v", ctyToInterface(v)))
						}
					}
				case t == cty.String:
					items = append(items, listVal.AsString())
				}
			}
			return cty.StringVal(strings.Join(items, sep)), nil
		},
	})
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
