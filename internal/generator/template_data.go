package generator

import (
	"fmt"
	"path/filepath"
	"strings"
)

// buildTemplateData assembles all values needed to render the Alloy template.
func (g *Generator) buildTemplateData() *TemplateData {
	data := &TemplateData{
		SourceFile: filepath.Base(g.sourceFile),
		Predicates: GeneratePredicates(),
	}

	// ── Tag values ───────────────────────────────────────────────────────
	tagList := g.sortedKeys(g.tags)
	tagIDs := make([]string, len(tagList))
	for i, t := range tagList {
		tagIDs[i] = TagToAlloyID(t)
	}
	data.TagValues = strings.Join(tagIDs, ", ")

	// ── VPCE IDs ─────────────────────────────────────────────────────────
	data.VpceIds = g.sortedKeys(g.vpces)

	// ── Action values ─────────────────────────────────────────────────────
	data.ActionValues = strings.Join(g.sortedKeys(g.actions), ", ")

	// ── S3 Buckets ────────────────────────────────────────────────────────
	bucketNames := make([]string, len(g.config.Buckets))
	for i, b := range g.config.Buckets {
		id := AlloyID(b.TFName)
		bucketNames[i] = id
		if b.BucketName != "" {
			g.bucketDisplay[id] = b.BucketName
		} else {
			g.bucketDisplay[id] = "aws_s3_bucket." + b.TFName
		}
	}
	data.Buckets = bucketNames
	data.BucketUnion = g.buildUnion(bucketNames, "bucket_")

	// ── Bucket Policies ───────────────────────────────────────────────────
	policyNames := make([]string, len(g.config.BucketPolicies))
	for i, p := range g.config.BucketPolicies {
		policyNames[i] = AlloyID(p.TFName)
	}
	data.BucketPolicies = policyNames
	data.BucketPolicyUnion = g.buildUnion(policyNames, "policy_")

	// ── OrgRCPs ───────────────────────────────────────────────────────────
	rcps := g.config.RCPs()
	rcpNames := make([]string, len(rcps))
	for i, r := range rcps {
		rcpNames[i] = AlloyID(r.TFName)
	}
	data.RCPs = rcpNames
	data.RCPUnion = g.buildUnion(rcpNames, "rcp_")

	// ── OrgSCPs ───────────────────────────────────────────────────────────
	scps := g.config.SCPs()
	scpNames := make([]string, len(scps))
	for i, s := range scps {
		scpNames[i] = AlloyID(s.TFName)
	}
	data.SCPs = scpNames
	data.SCPUnion = g.buildUnion(scpNames, "scp_")

	// ── IAM Roles ─────────────────────────────────────────────────────────
	roleNames := make([]string, len(g.config.Roles))
	for i, r := range g.config.Roles {
		id := AlloyID(r.TFName)
		roleNames[i] = id
		if r.Name != "" {
			g.principalDisplay[id] = r.Name
		} else {
			g.principalDisplay[id] = "aws_iam_role." + r.TFName
		}
	}
	data.Roles = roleNames
	data.RoleUnion = g.buildUnion(roleNames, "role_")

	// ── IAM Users ─────────────────────────────────────────────────────────
	userNames := make([]string, len(g.config.Users))
	for i, u := range g.config.Users {
		id := AlloyID(u.TFName)
		userNames[i] = id
		if u.Name != "" {
			g.principalDisplay[id] = u.Name
		} else {
			g.principalDisplay[id] = "aws_iam_user." + u.TFName
		}
	}
	data.Users = userNames
	data.UserUnion = g.buildUnion(userNames, "user_")

	// ── Service Principals ────────────────────────────────────────────────
	svcNames := make([]string, len(g.config.ServicePrincipals))
	for i, sp := range g.config.ServicePrincipals {
		id := AlloyID(sp.TFName)
		svcNames[i] = id
		g.principalDisplay[id] = sp.Name
	}
	data.ServicePrincipals = svcNames
	data.ServicePrincipalUnion = g.buildUnion(svcNames, "svc_")

	// ── Config facts ──────────────────────────────────────────────────────
	data.ConfigFacts = g.buildConfigFacts()

	// ── Build principals list for TripleMetadata() and assertions ─────────
	sortedActions := g.sortedKeys(g.actions)
	principals := make([]PrincipalEntry, 0, len(roleNames)+len(userNames)+len(svcNames))
	for _, r := range g.config.Roles {
		n := AlloyID(r.TFName)
		principals = append(principals, PrincipalEntry{
			Name:             n,
			SigName:          "role_" + n,
			HasSessionPolicy: r.HasSessionPolicy,
		})
	}
	for _, n := range userNames {
		// IAM users never have session policies in static Terraform analysis.
		principals = append(principals, PrincipalEntry{Name: n, SigName: "user_" + n})
	}
	for _, n := range svcNames {
		// Service principals have no session policies, boundaries, or identity policies.
		principals = append(principals, PrincipalEntry{Name: n, SigName: "svc_" + n})
	}
	g.principals = principals
	g.bucketNames = bucketNames
	g.actionNames = sortedActions

	// ── Per-triple access assertions (combined + per-layer) ──────────────
	data.AccessAssertions = GenerateAccessAssertionsForPrincipals(
		g.principals, bucketNames, sortedActions,
	)

	// ── Scope & checks ────────────────────────────────────────────────────
	actionCount := len(sortedActions)
	tagCount := len(g.sortedKeys(g.tags))
	vpceCount := len(g.sortedKeys(g.vpces))

	// Request count: need at least one atom per (principal, bucket, action) triple.
	principalCount := len(g.config.Roles) + len(g.config.Users) + len(g.config.ServicePrincipals)
	requestCount := principalCount * len(g.config.Buckets) * actionCount
	if requestCount < 1 {
		requestCount = 1
	}

	scope := fmt.Sprintf(
		"for exactly %d S3Bucket, exactly %d BucketPolicy,\n"+
			"      exactly %d OrgRCP, exactly %d OrgSCP,\n"+
			"      exactly %d IAMRole, exactly %d IAMUser, exactly %d ServicePrincipal, exactly %d Request,\n"+
			"      exactly %d VpceId, exactly %d TagValue,\n"+
			"      exactly %d Action, exactly 2 Bool",
		len(g.config.Buckets), len(g.config.BucketPolicies),
		len(rcps), len(scps),
		len(g.config.Roles), len(g.config.Users), len(g.config.ServicePrincipals), requestCount,
		vpceCount, tagCount,
		actionCount,
	)

	data.Checks = GenerateChecks(scope, data.AccessAssertions)

	return data
}

// buildUnion creates an Alloy union expression: "prefix_a + prefix_b" or "none".
func (g *Generator) buildUnion(names []string, prefix string) string {
	if len(names) == 0 {
		return "none"
	}
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = prefix + n
	}
	return strings.Join(parts, " + ")
}
