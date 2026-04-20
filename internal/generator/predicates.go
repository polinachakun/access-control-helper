package generator

import (
	"fmt"
	"strings"
)

// GeneratePredicates returns all AWS policy evaluation predicates for all 7 layers.
// The predicates mirror the exact AWS S3 evaluation order:
//
//	Layer 1 – Explicit Deny check
//	Layer 2 – AWS Organizations RCPs (Resource Control Policies)
//	Layer 3 – AWS Organizations SCPs (Service Control Policies)
//	Layer 4 – Resource-based policies (S3 bucket policy)
//	Layer 5 – Identity-based policies (IAM role / user policies)
//	Layer 6 – IAM Permission Boundaries
//	Layer 7 – Session Policies
func GeneratePredicates() []Predicate {
	return []Predicate{
		// ── Layer 1: Explicit Deny ────────────────────────────────────────────
		{
			Name:    "explicitDenyVpce",
			Params:  []string{"req: Request"},
			Comment: "Layer 1a: VPCE guard — deny applies only if statement resource scope matches the action.",
			Body: `some bp: BucketPolicy |
    bp.bucket = req.target and
    bp.denyAllExcept != none and
    statementMatchesResource[req, bp.denyBucketResource, bp.denyObjectResource] and
    req.sourceVpce != bp.denyAllExcept`,
		},
		{
			Name:    "explicitDenyAction",
			Params:  []string{"req: Request"},
			Comment: "Layer 1b: Explicit Deny statement in bucket policy matching action, principal, and resource scope.",
			Body: `some bp: BucketPolicy |
    bp.bucket = req.target and
    req.action in bp.denyActions and
    statementMatchesResource[req, bp.denyBucketResource, bp.denyObjectResource] and
    (bp.denyAnyPrincipal = True or bp.denyPrincipal = req.principal)`,
		},
		{
			Name:    "explicitDeny",
			Params:  []string{"req: Request"},
			Comment: "Layer 1: Any explicit deny fires — VPCE guard OR explicit Deny statement wins immediately.",
			Body:    `explicitDenyVpce[req] or explicitDenyAction[req]`,
		},

		// ── Layer 2: AWS Organizations RCPs ─────────────────────────────────
		{
			Name:    "rcpAllows",
			Params:  []string{"req: Request"},
			Comment: "Layer 2: AWS Organizations RCPs — action must be allowed by every RCP; no RCP means pass-through.",
			Body: `no OrgRCP or
  (all rcp: OrgRCP |
    req.action in rcp.rcpAllowActions and
    req.action not in rcp.rcpDenyActions)`,
		},

		// ── Layer 3: AWS Organizations SCPs ─────────────────────────────────
		{
			Name:    "scpAllows",
			Params:  []string{"req: Request"},
			Comment: "Layer 3: AWS Organizations SCPs — action must be allowed by every SCP; no SCP means pass-through.",
			Body: `no OrgSCP or
  (all scp: OrgSCP |
    req.action in scp.scpAllowActions and
    req.action not in scp.scpDenyActions)`,
		},

		// ── Layer 4: Resource-Based Policy ──────────────────────────────────
		{
			Name:    "resourcePolicyAllows",
			Params:  []string{"req: Request"},
			Comment: "Layer 4: Resource-based policy — statement must match principal, action, resource scope, and ABAC condition.",
			Body: `some bp: BucketPolicy |
    bp.bucket = req.target and
    req.action in bp.allowActions and
    statementMatchesResource[req, bp.allowBucketResource, bp.allowObjectResource] and
    (bp.allowAnyPrincipal = True or bp.allowPrincipal = req.principal) and
    (bp.abacCondition = True implies
       req.principal.envTag = req.target.envTag)`,
		},

		// ── Layer 4 helper: no resource-based policy applies ────────────────
		{
			Name:    "resourcePolicyNotApplicable",
			Params:  []string{"req: Request"},
			Comment: "Layer 4: No resource-based policy applies to this request's target bucket.",
			Body:    `no bp: BucketPolicy | bp.bucket = req.target`,
		},

		// ── Layer 5: Identity-Based Policy ──────────────────────────────────
		{
			Name:    "identityPolicyAllows",
			Params:  []string{"req: Request"},
			Comment: "Layer 5: Identity-based policy — the IAM role has a policy that explicitly allows the action.",
			Body: `req.principal.hasRolePolicy = True and
  req.action in req.principal.roleAllowActions`,
		},

		// ── Layer 6: IAM Permission Boundary ────────────────────────────────
		{
			Name:    "permBoundaryAllows",
			Params:  []string{"req: Request"},
			Comment: "Layer 6: IAM Permission Boundary — if a boundary is set, the action must appear in its allow set.",
			Body: `req.principal.hasBoundary = False or
  req.action in req.principal.boundaryActions`,
		},

		// ── Layer 7: Session Policy ──────────────────────────────────────────
		{
			Name:    "sessionPolicyAllows",
			Params:  []string{"req: Request"},
			Comment: "Layer 7: Session Policy — if a session policy is present, the action must appear in its allow set.",
			Body: `req.principal.hasSessionPolicy = False or
  req.action in req.principal.sessionPolicyActions`,
		},

		// ── Combined Access Decision ─────────────────────────────────────────
		{
			Name:    "accessAllowed",
			Params:  []string{"req: Request"},
			Comment: "Final: no explicit deny, limiting layers pass, and at least one grant path allows.",
			Body: `not explicitDeny[req] and
  rcpAllows[req] and
  scpAllows[req] and
  grantPathAllows[req] and
  permBoundaryAllows[req] and
  sessionPolicyAllows[req]`,
		},
		{
			Name:    "grantPathAllows",
			Params:  []string{"req: Request"},
			Comment: "At least one same-account grant path allows the request.",
			Body:    `resourcePolicyAllows[req] or identityPolicyAllows[req]`,
		},
		{
			Name:    "actionTargetsBucket",
			Params:  []string{"a: Action"},
			Comment: "True for bucket-level S3 actions.",
			Body:    `a = S3_ListBucket`,
		},
		{
			Name:    "actionTargetsObject",
			Params:  []string{"a: Action"},
			Comment: "True for object-level S3 actions.",
			Body:    `a = S3_GetObject`,
		},
		{
			Name:    "statementMatchesResource",
			Params:  []string{"req: Request, bucketRes: Bool, objectRes: Bool"},
			Comment: "A policy statement applies only when its resource scope matches the action's required S3 resource type.",
			Body: `(actionTargetsBucket[req.action] and bucketRes = True) or
  (actionTargetsObject[req.action] and objectRes = True)`,
		},
	}
}

// LayerPredicateInfo describes a per-layer Alloy assertion predicate.
type LayerPredicateInfo struct {
	Suffix    string
	Predicate string
	Comment   string
	Kind      string // "blocking" or "granting"
}

// LayerPredicates maps a layer suffix to the Alloy predicate that checks it.
var LayerPredicates = []LayerPredicateInfo{
	{"_L1", "not explicitDeny[req]", "Layer 1: No explicit deny", "blocking"},
	{"_L2", "rcpAllows[req]", "Layer 2: RCP allows", "blocking"},
	{"_L3", "scpAllows[req]", "Layer 3: SCP allows", "blocking"},
	{"_L4", "resourcePolicyAllows[req] or resourcePolicyNotApplicable[req]", "Layer 4: Resource policy allows or not applicable", "granting"},
	{"_L5", "identityPolicyAllows[req]", "Layer 5: Identity policy allows", "granting"},
	{"_L6", "permBoundaryAllows[req]", "Layer 6: Permission boundary allows", "blocking"},
	{"_L7", "sessionPolicyAllows[req]", "Layer 7: Session policy allows", "blocking"},
}

// TripleKey maps a base assertion name back to its human-readable components.
type TripleKey struct {
	Role              string
	Bucket            string
	Action            string
	AssertionBaseName string
}

// BuildTripleKeys computes a TripleKey for every (role, bucket, action) combination.
func BuildTripleKeys(roleNames, bucketNames, actionNames []string) []TripleKey {
	var keys []TripleKey
	for _, role := range roleNames {
		for _, bucket := range bucketNames {
			for _, action := range actionNames {
				name := tripleBaseName(role, bucket, action)
				keys = append(keys, TripleKey{
					Role:              role,
					Bucket:            bucket,
					Action:            action,
					AssertionBaseName: name,
				})
			}
		}
	}
	return keys
}

// tripleBaseName returns the PascalCase assertion base name for a triple.
func tripleBaseName(role, bucket, action string) string {
	return toPascalCase(role) +
		"Can" + toPascalCase(trimPrefix(action, "S3_")) +
		"On" + toPascalCase(bucket)
}

// GenerateAccessAssertions creates 8 assertions per (role, bucket, action) triple:
// one combined assertion (accessAllowed) plus one per evaluation layer (L1–L7).
func GenerateAccessAssertions(roleNames, bucketNames, actionNames []string) []Assertion {
	var assertions []Assertion
	for _, role := range roleNames {
		for _, bucket := range bucketNames {
			for _, action := range actionNames {
				baseName := tripleBaseName(role, bucket, action)
				reqMatch := fmt.Sprintf(
					`req.principal = role_%s and
     req.action = %s and
     req.target = bucket_%s`, role, action, bucket)

				// Combined assertion: accessAllowed
				assertions = append(assertions, Assertion{
					Name:    baseName,
					Comment: fmt.Sprintf("Checks if %s can perform %s on %s.", role, action, bucket),
					Body: fmt.Sprintf(`all req: Request |
    (%s)
    implies accessAllowed[req]`, reqMatch),
				})

				// Per-layer assertions
				for _, lp := range LayerPredicates {
					assertions = append(assertions, Assertion{
						Name:    baseName + lp.Suffix,
						Comment: fmt.Sprintf("%s for %s performing %s on %s.", lp.Comment, role, action, bucket),
						Body: fmt.Sprintf(`all req: Request |
    (%s)
    implies %s`, reqMatch, lp.Predicate),
					})
				}
			}
		}
	}
	return assertions
}

// GenerateChecks returns check commands for the given assertions with the given scope.
func GenerateChecks(scope string, assertions []Assertion) []Check {
	checks := make([]Check, len(assertions))
	for i, a := range assertions {
		checks[i] = Check{AssertionName: a.Name, Scope: scope}
	}
	return checks
}

// toPascalCase converts a snake_case or camelCase string to PascalCase.
func toPascalCase(s string) string {
	parts := strings.Split(s, "_")
	for i, p := range parts {
		parts[i] = capitalizeFirst(p)
	}
	return strings.Join(parts, "")
}

// capitalizeFirst uppercases the first character of s.
func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// stripUnderscores removes underscores from s.
func stripUnderscores(s string) string {
	return strings.ReplaceAll(s, "_", "")
}

// trimPrefix removes a leading prefix if present.
func trimPrefix(s, prefix string) string {
	return strings.TrimPrefix(s, prefix)
}
