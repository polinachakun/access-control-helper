package generator

// GeneratePredicates returns all AWS evaluation step predicates.
func GeneratePredicates() []Predicate {
	return []Predicate{
		{
			Name:    "explicitDeny",
			Params:  []string{"req: Request"},
			Comment: "Step 1: Explicit Deny - VPCE guard blocks requests without correct VPCE",
			Body: `some bp: BucketPolicy |
    bp.bucket        = req.target and
    bp.denyAllExcept != none      and
    req.sourceVpce  != bp.denyAllExcept`,
		},
		{
			Name:    "resourcePolicyAllows",
			Params:  []string{"req: Request"},
			Comment: "Step 3: Resource Policy - bucket policy must allow principal + action + ABAC",
			Body: `some bp: BucketPolicy |
    bp.bucket         = req.target    and
    bp.allowPrincipal = req.principal and
    req.action in bp.allowActions     and
    (bp.abacCondition = True implies
       req.principal.envTag = req.target.envTag)`,
		},
		{
			Name:    "identityPolicyAllows",
			Params:  []string{"req: Request"},
			Comment: "Step 6: Identity Policy - role must have policy allowing action",
			Body: `req.principal.hasRolePolicy = True and
  req.action in req.principal.roleAllowActions`,
		},
		{
			Name:    "accessAllowed",
			Params:  []string{"req: Request"},
			Comment: "Final: no explicit deny, and either bucket policy OR identity policy grants access",
			Body: `not explicitDeny[req] and
  (resourcePolicyAllows[req] or identityPolicyAllows[req])`,
		},
	}
}

// GenerateAssertions returns assertions that detect misconfigurations.
// These fail when there's a bug in the Terraform config.
// policyName may be empty when the scenario has no bucket policy.
func GenerateAssertions(bucketName, policyName, roleName string) []Assertion {
	assertions := []Assertion{}

	if bucketName == "" || roleName == "" {
		return assertions
	}

	if policyName != "" {
		// Full check: role should have access using the correct VPCE from the bucket policy.
		assertions = append(assertions, Assertion{
			Name:    "RoleHasAccess",
			Comment: "Main check: role should have access to bucket via correct VPCE. Fails on ANY misconfiguration.",
			Body: `all req: Request |
    (req.principal = role_` + roleName + ` and
     req.action = S3_GetObject and
     req.target = bucket_` + bucketName + ` and
     req.sourceVpce = policy_` + policyName + `.denyAllExcept)
    implies accessAllowed[req]`,
		})
		assertions = append(assertions, Assertion{
			Name:    "NoVpceBypass",
			Comment: "Step 1: Requests with wrong VPCE should be denied. Fails if denyAllExcept = none.",
			Body: `all req: Request |
    (req.principal = role_` + roleName + ` and
     req.target = bucket_` + bucketName + ` and
     req.sourceVpce = VPCE_OTHER)
    implies explicitDeny[req]`,
		})
		assertions = append(assertions, Assertion{
			Name:    "NoStep3Deny",
			Comment: "Step 3: Role should pass resource policy. Fails on ABAC tag mismatch or missing allow.",
			Body: `all req: Request |
    (req.principal = role_` + roleName + ` and
     req.action = S3_GetObject and
     req.target = bucket_` + bucketName + `)
    implies resourcePolicyAllows[req]`,
		})
	} else {
		// No bucket policy: access is granted via identity policy alone.
		assertions = append(assertions, Assertion{
			Name:    "RoleHasAccess",
			Comment: "Main check: role should have access to bucket via identity policy (no bucket policy present).",
			Body: `all req: Request |
    (req.principal = role_` + roleName + ` and
     req.action = S3_GetObject and
     req.target = bucket_` + bucketName + `)
    implies accessAllowed[req]`,
		})
	}

	// Step 6 (identity policy) assertion is always relevant.
	assertions = append(assertions, Assertion{
		Name:    "NoStep6Deny",
		Comment: "Step 6: Role should pass identity policy. Fails if hasRolePolicy = False or action not in policy.",
		Body: `all req: Request |
    (req.principal = role_` + roleName + ` and
     req.action = S3_GetObject and
     req.target = bucket_` + bucketName + `)
    implies identityPolicyAllows[req]`,
	})

	return assertions
}

// GenerateChecks returns check commands for all assertions.
func GenerateChecks(scope string, assertions []Assertion) []Check {
	checks := make([]Check, len(assertions))
	for i, a := range assertions {
		checks[i] = Check{
			AssertionName: a.Name,
			Scope:         scope,
		}
	}
	return checks
}
