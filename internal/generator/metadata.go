package generator

import (
	"sort"

	"access-control-helper/internal/ir"
)

func (g *Generator) sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TripleMetadata returns a TripleKey for every (principal, bucket, action) triple.
// Must be called after GenerateToFile or GenerateToWriter.
func (g *Generator) TripleMetadata() []TripleKey {
	keys := BuildTripleKeysFromPrincipals(g.principals, g.bucketNames, g.actionNames)
	for i := range keys {
		if d, ok := g.principalDisplay[keys[i].Principal]; ok {
			keys[i].PrincipalDisplay = d
		}
		if d, ok := g.bucketDisplay[keys[i].Bucket]; ok {
			keys[i].BucketDisplay = d
		}
		if hasCA, conds, policyName := g.findConditionalAllow(keys[i].Principal, keys[i].Bucket, keys[i].Action); hasCA {
			keys[i].HasConditionalAllow = true
			keys[i].ConditionalAllowConditions = conds
			keys[i].ConditionalAllowedBy = policyName
		}
	}
	return keys
}

// findConditionalAllow returns true (plus the conditions and originating policy name)
// when a bucket policy grants the given triple but carries unrecognized conditions —
// meaning the grant is conditional at runtime and cannot be statically verified.
func (g *Generator) findConditionalAllow(principalAlloyID, bucketAlloyID, actionAlloyID string) (bool, []ir.Condition, string) {
	bucketRef := ""
	for _, b := range g.config.Buckets {
		if AlloyID(b.TFName) == bucketAlloyID {
			bucketRef = "aws_s3_bucket." + b.TFName
			break
		}
	}
	if bucketRef == "" {
		return false, nil, ""
	}

	for _, bp := range g.config.BucketPolicies {
		if len(bp.AllowUnrecognizedConditions) == 0 {
			continue
		}
		if bp.BucketRef != bucketRef {
			continue
		}

		actionAllowed := false
		if bp.HasAllowNotAction {
			if HasWildcardActions(bp.AllowNotActions) {
				actionAllowed = false // NotAction: s3:* — nothing is allowed
			} else {
				actionAllowed = true
				for _, a := range ExpandAnalyzableActions(bp.AllowNotActions) {
					if ActionToAlloyID(a) == actionAlloyID {
						actionAllowed = false
						break
					}
				}
			}
		} else {
			if HasWildcardActions(bp.AllowActions) {
				actionAllowed = true // s3:* grants all actions
			} else {
				for _, a := range ExpandAnalyzableActions(bp.AllowActions) {
					if ActionToAlloyID(a) == actionAlloyID {
						actionAllowed = true
						break
					}
				}
			}
		}
		if !actionAllowed {
			continue
		}

		principalCovered := bp.AllowAnyPrincipal
		if !principalCovered {
			for _, prin := range bp.AllowPrincipals {
				sig := resolvePrincipalSig(prin, g.config)
				if sig == "role_"+principalAlloyID ||
					sig == "user_"+principalAlloyID ||
					sig == "svc_"+principalAlloyID {
					principalCovered = true
					break
				}
			}
		}
		if !principalCovered {
			continue
		}

		return true, bp.AllowUnrecognizedConditions, bp.OriginalPolicyTFName
	}
	return false, nil, ""
}
