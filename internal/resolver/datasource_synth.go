package resolver

import (
	"encoding/json"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"access-control-helper/internal/parser"
)

func arnPlaceholder(resType, resName string) string {
	switch resType {
	case "aws_s3_bucket":
		return fmt.Sprintf("arn:aws:s3:::%s", resName)
	default:
		return fmt.Sprintf("arn:aws::::%s", resName)
	}
}

func (r *Resolver) synthesizeDataSources(parseResult *parser.ParseResult) {
	policyDocVals := make(map[string]cty.Value)

	for i := range parseResult.DataSources {
		ds := &parseResult.DataSources[i]
		if ds.Type != "aws_iam_policy_document" {
			continue
		}
		jsonStr := r.synthesizePolicyDocJSON(ds)
		if jsonStr == "" {
			continue
		}
		policyDocVals[ds.Name] = cty.ObjectVal(map[string]cty.Value{
			"json": cty.StringVal(jsonStr),
			"id":   cty.StringVal(ds.Name),
		})
	}

	if len(policyDocVals) == 0 {
		return
	}

	dataVals := make(map[string]cty.Value)
	existing := r.evalCtx.Variables["data"]
	if existing != cty.NilVal && !existing.IsNull() && existing.Type().IsObjectType() {
		for it := existing.ElementIterator(); it.Next(); {
			k, v := it.Element()
			dataVals[k.AsString()] = v
		}
	}
	dataVals["aws_iam_policy_document"] = cty.ObjectVal(policyDocVals)
	r.evalCtx.Variables["data"] = cty.ObjectVal(dataVals)
}

// synthesizePolicyDocJSON converts a data "aws_iam_policy_document" RawResource
// into a valid IAM policy JSON string by evaluating its statement blocks.
func (r *Resolver) synthesizePolicyDocJSON(ds *parser.RawResource) string {
	for _, dynBlock := range ds.Blocks["dynamic"] {
		blockType := "statement"
		if len(dynBlock.Labels) > 0 {
			blockType = dynBlock.Labels[0]
		}
		r.warnings = append(r.warnings, fmt.Sprintf(
			"data.aws_iam_policy_document.%s: dynamic %q block cannot be statically evaluated; affected statements skipped (analysis is a lower bound)",
			ds.Name, blockType))
	}

	var stmts []map[string]interface{}

	for _, stmtBlock := range ds.Blocks["statement"] {
		stmt := make(map[string]interface{})

		if sid := r.blockAttrStr(stmtBlock, "sid"); sid != "" {
			stmt["Sid"] = sid
		}

		effect := r.blockAttrStr(stmtBlock, "effect")
		if effect == "" {
			effect = "Allow"
		}
		stmt["Effect"] = effect

		if actions := r.blockAttrStrs(stmtBlock, "actions"); len(actions) > 0 {
			stmt["Action"] = actions
		}
		if notActions := r.blockAttrStrs(stmtBlock, "not_actions"); len(notActions) > 0 {
			stmt["NotAction"] = notActions
		}
		if resources := r.blockAttrStrs(stmtBlock, "resources"); len(resources) > 0 {
			stmt["Resource"] = resources
		}
		if notResources := r.blockAttrStrs(stmtBlock, "not_resources"); len(notResources) > 0 {
			stmt["NotResource"] = notResources
		}

		if p := r.synthesizePrincipals(stmtBlock.Blocks["principals"]); p != nil {
			stmt["Principal"] = p
		}
		if np := r.synthesizePrincipals(stmtBlock.Blocks["not_principals"]); np != nil {
			stmt["NotPrincipal"] = np
		}
		if conds := r.synthesizeConditions(stmtBlock.Blocks["condition"]); conds != nil {
			stmt["Condition"] = conds
		}

		stmts = append(stmts, stmt)
	}

	doc := map[string]interface{}{
		"Version":   "2012-10-17",
		"Statement": stmts,
	}

	b, err := json.Marshal(doc)
	if err != nil {
		return ""
	}
	return string(b)
}

func (r *Resolver) blockAttrStr(block parser.RawBlock, name string) string {
	expr, ok := block.Attributes[name]
	if !ok || expr == nil {
		return ""
	}
	if s, ok := r.resolveExpression(expr).(string); ok {
		return s
	}
	return ""
}

func (r *Resolver) blockAttrStrs(block parser.RawBlock, name string) []string {
	expr, ok := block.Attributes[name]
	if !ok || expr == nil {
		return nil
	}
	val := r.resolveExpression(expr)
	switch v := val.(type) {
	case string:
		return []string{v}
	case []interface{}:
		ss := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				ss = append(ss, s)
			}
		}
		return ss
	}
	return nil
}

// synthesizePrincipals converts principals/not_principals blocks to the JSON
// Principal value: either "*" (string) or {"AWS": [...], "Service": [...]} (object).
func (r *Resolver) synthesizePrincipals(blocks []parser.RawBlock) interface{} {
	if len(blocks) == 0 {
		return nil
	}
	for _, block := range blocks {
		pType := r.blockAttrStr(block, "type")
		identifiers := r.blockAttrStrs(block, "identifiers")
		if pType == "*" || (len(identifiers) == 1 && identifiers[0] == "*") {
			return "*"
		}
	}
	principalMap := make(map[string][]string)
	for _, block := range blocks {
		pType := r.blockAttrStr(block, "type")
		identifiers := r.blockAttrStrs(block, "identifiers")
		if pType != "" {
			principalMap[pType] = append(principalMap[pType], identifiers...)
		}
	}
	if len(principalMap) == 0 {
		return nil
	}
	return principalMap
}

// synthesizeConditions converts condition blocks to the JSON Condition object:
// {"Operator": {"Key": ["values"]}}.
func (r *Resolver) synthesizeConditions(blocks []parser.RawBlock) map[string]map[string]interface{} {
	if len(blocks) == 0 {
		return nil
	}
	conds := make(map[string]map[string]interface{})
	for _, block := range blocks {
		test := r.blockAttrStr(block, "test")
		variable := r.blockAttrStr(block, "variable")
		values := r.blockAttrStrs(block, "values")
		if test == "" || variable == "" {
			continue
		}
		if conds[test] == nil {
			conds[test] = make(map[string]interface{})
		}
		if len(values) == 1 {
			conds[test][variable] = values[0]
		} else {
			conds[test][variable] = values
		}
	}
	if len(conds) == 0 {
		return nil
	}
	return conds
}
