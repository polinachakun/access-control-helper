package generator

import "strings"

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
			Comment: "Layer 1a: VPCE guard — bucket policy denies requests without the required VPCE.",
			Body: `some bp: BucketPolicy |
    bp.bucket        = req.target and
    bp.denyAllExcept != none      and
    req.sourceVpce  != bp.denyAllExcept`,
		},
		{
			Name:    "explicitDenyAction",
			Params:  []string{"req: Request"},
			Comment: "Layer 1b: Explicit Deny statement in bucket policy matching action and (optionally) principal.",
			Body: `some bp: BucketPolicy |
    bp.bucket = req.target and
    req.action in bp.denyActions and
    (bp.denyPrincipal = none or bp.denyPrincipal = req.principal)`,
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
			Comment: "Layer 4: Resource-based policy — bucket policy allows principal + action (+ ABAC tag match when required).",
			Body: `some bp: BucketPolicy |
    bp.bucket         = req.target    and
    bp.allowPrincipal = req.principal and
    req.action in bp.allowActions     and
    (bp.abacCondition = True implies
       req.principal.envTag = req.target.envTag)`,
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
			Comment: "Final: all 7 layers must pass — no explicit deny and at least one grant path (resource OR identity policy).",
			Body: `not explicitDeny[req] and
  rcpAllows[req] and
  scpAllows[req] and
  (resourcePolicyAllows[req] or identityPolicyAllows[req]) and
  permBoundaryAllows[req] and
  sessionPolicyAllows[req]`,
		},
	}
}

// GenerateScenarioAssertions returns assertions that verify all 7 evaluation layers
// for the primary (role, bucket) pair in the scenario. An assertion FAILS (counterexample
// found) when the corresponding layer denies access for that triple.
func GenerateScenarioAssertions(bucketName, policyName, roleName string) []Assertion {
	if bucketName == "" || roleName == "" {
		return nil
	}

	triple := func(extra string) string {
		base := `req.principal = role_` + roleName + ` and
     req.action = S3_GetObject and
     req.target = bucket_` + bucketName
		if extra != "" {
			return base + ` and
     ` + extra
		}
		return base
	}

	var assertions []Assertion

	// ── Main overall access check ────────────────────────────────────────
	if policyName != "" {
		assertions = append(assertions, Assertion{
			Name:    "RoleHasAccess",
			Comment: "Main: role must reach the bucket with the correct VPCE (all 7 layers pass).",
			Body: `all req: Request |
    (` + triple(`req.sourceVpce = policy_`+policyName+`.denyAllExcept`) + `)
    implies accessAllowed[req]`,
		})
		assertions = append(assertions, Assertion{
			Name:    "NoVpceBypass",
			Comment: "Layer 1: Requests with the wrong VPCE must be denied — verifies the VPCE guard is active.",
			Body: `all req: Request |
    (req.principal = role_` + roleName + ` and
     req.target = bucket_` + bucketName + ` and
     req.sourceVpce = VPCE_OTHER)
    implies explicitDeny[req]`,
		})
		assertions = append(assertions, Assertion{
			Name:    "NoLayer4Deny",
			Comment: "Layer 4: Bucket policy must allow the principal + S3:GetObject.",
			Body:    `all req: Request | (` + triple("") + `) implies resourcePolicyAllows[req]`,
		})
	} else {
		assertions = append(assertions, Assertion{
			Name:    "RoleHasAccess",
			Comment: "Main: role must have access via identity policy (no bucket policy present).",
			Body:    `all req: Request | (` + triple("") + `) implies accessAllowed[req]`,
		})
	}

	// ── Per-layer assertions (trivially true when layer is not applicable) ──
	assertions = append(assertions,
		Assertion{
			Name:    "NoLayer2Deny",
			Comment: "Layer 2: RCP must allow S3:GetObject (passes trivially when no RCPs are configured).",
			Body:    `all req: Request | (` + triple("") + `) implies rcpAllows[req]`,
		},
		Assertion{
			Name:    "NoLayer3Deny",
			Comment: "Layer 3: SCP must allow S3:GetObject (passes trivially when no SCPs are configured).",
			Body:    `all req: Request | (` + triple("") + `) implies scpAllows[req]`,
		},
		Assertion{
			Name:    "NoLayer5Deny",
			Comment: "Layer 5: Identity policy must allow S3:GetObject.",
			Body:    `all req: Request | (` + triple("") + `) implies identityPolicyAllows[req]`,
		},
		Assertion{
			Name:    "NoLayer6Deny",
			Comment: "Layer 6: Permission boundary must allow S3:GetObject (passes trivially when no boundary is set).",
			Body:    `all req: Request | (` + triple("") + `) implies permBoundaryAllows[req]`,
		},
		Assertion{
			Name:    "NoLayer7Deny",
			Comment: "Layer 7: Session policy must allow S3:GetObject (passes trivially when no session policy is set).",
			Body:    `all req: Request | (` + triple("") + `) implies sessionPolicyAllows[req]`,
		},
	)

	return assertions
}

// GenerateAssertions is the legacy wrapper kept for backwards compatibility.
// Prefer GenerateScenarioAssertions for new call sites.
func GenerateAssertions(bucketName, policyName, roleName string) []Assertion {
	return GenerateScenarioAssertions(bucketName, policyName, roleName)
}

// GenerateAccessAssertions creates one assertion per (role, bucket, action) triple.
// Each assertion checks that accessAllowed holds for every request matching the triple.
// A check FAILS (counterexample found by Alloy) when access is DENIED for that triple.
func GenerateAccessAssertions(roleNames, bucketNames, actionNames []string) []Assertion {
	var assertions []Assertion
	for _, role := range roleNames {
		for _, bucket := range bucketNames {
			for _, action := range actionNames {
				name := toPascalCase(role) +
					"Can" + toPascalCase(trimPrefix(action, "S3_")) +
					"On" + toPascalCase(bucket)
				assertions = append(assertions, Assertion{
					Name:    name,
					Comment: "Checks if " + role + " can perform " + action + " on " + bucket + ".",
					Body: `all req: Request |
    (req.principal = role_` + role + ` and
     req.action = ` + action + ` and
     req.target = bucket_` + bucket + `)
    implies accessAllowed[req]`,
				})
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
