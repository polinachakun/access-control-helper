package generator

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"access-control-helper/internal/ir"
)

// Generator produces Alloy specifications from an IR Config.
type Generator struct {
	config     *ir.Config
	sourceFile string

	tags    map[string]bool
	vpces   map[string]bool
	actions map[string]bool

	principals       []PrincipalEntry
	bucketNames      []string
	actionNames      []string
	principalDisplay map[string]string
	bucketDisplay    map[string]string

	// wildcardLayers tracks which evaluation layers had wildcard actions (e.g. s3:*).
	wildcardLayers []string
}

// NewGenerator creates a new Generator.
func NewGenerator(config *ir.Config, sourceFile string) *Generator {
	return &Generator{
		config:           config,
		sourceFile:       sourceFile,
		tags:             make(map[string]bool),
		vpces:            make(map[string]bool),
		actions:          make(map[string]bool),
		principalDisplay: make(map[string]string),
		bucketDisplay:    make(map[string]string),
	}
}

// GenerateToFile writes the Alloy specification to outputPath.
func (g *Generator) GenerateToFile(outputPath string) error {
	g.collectValues()
	data := g.buildTemplateData()
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()
	if err := RenderTemplate(f, data); err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}
	return nil
}

// GenerateToWriter writes the Alloy specification to any io.Writer.
func (g *Generator) GenerateToWriter(w io.Writer) error {
	g.collectValues()
	data := g.buildTemplateData()
	return RenderTemplate(w, data)
}

// WildcardLayers returns the ordered list of evaluation layer labels where a
// wildcard action (e.g. s3:*) was detected. Empty when all actions are explicit.
func (g *Generator) WildcardLayers() []string { return g.wildcardLayers }

// WildcardFate describes what happens to S3 actions not explicitly analyzed
// when one or more policy layers grant s3:*.
type WildcardFate struct {
	HasWildcard      bool
	BlockingLayer    string // first layer that blocks unlisted actions, e.g. "Layer 6 (permission boundary)"
	BlockingReason   string // e.g. "permission boundary restricts to [s3:GetObject] only"
	EffectivelyAllow bool   // true when wildcard is present and no blocking layer exists
}

// ComputeWildcardFate determines what happens to unlisted S3 actions by inspecting
// each evaluation layer in AWS order. Must be called after GenerateToFile/Writer.
func (g *Generator) ComputeWildcardFate() WildcardFate {
	if len(g.wildcardLayers) == 0 {
		return WildcardFate{}
	}

	fate := WildcardFate{HasWildcard: true}

	// Layer 1: explicit deny for all S3 actions in identity or bucket policy.
	for _, r := range g.config.Roles {
		if HasWildcardActions(r.RoleDenyActions) {
			fate.BlockingLayer = "Layer 1"
			fate.BlockingReason = "identity policy explicitly denies all S3 actions"
			return fate
		}
	}
	for _, u := range g.config.Users {
		if HasWildcardActions(u.UserDenyActions) {
			fate.BlockingLayer = "Layer 1"
			fate.BlockingReason = "identity policy explicitly denies all S3 actions"
			return fate
		}
	}
	for _, bp := range g.config.BucketPolicies {
		if HasWildcardActions(bp.DenyActions) {
			fate.BlockingLayer = "Layer 1"
			fate.BlockingReason = "bucket policy explicitly denies all S3 actions"
			return fate
		}
	}

	// Layer 2: RCP with explicit (non-wildcard) allow list.
	for _, op := range g.config.RCPs() {
		if len(op.AllowActions) > 0 && !HasWildcardActions(op.AllowActions) {
			explicit := ExpandAnalyzableActions(op.AllowActions)
			fate.BlockingLayer = "Layer 2 (RCP)"
			fate.BlockingReason = fmt.Sprintf("RCP restricts to [%s] only", strings.Join(explicit, ", "))
			return fate
		}
	}

	// Layer 3: SCP with explicit (non-wildcard) allow list.
	for _, op := range g.config.SCPs() {
		if len(op.AllowActions) > 0 && !HasWildcardActions(op.AllowActions) {
			explicit := ExpandAnalyzableActions(op.AllowActions)
			fate.BlockingLayer = "Layer 3 (SCP)"
			fate.BlockingReason = fmt.Sprintf("SCP restricts to [%s] only", strings.Join(explicit, ", "))
			return fate
		}
	}

	// Layer 6: permission boundary with explicit (non-wildcard) allow list.
	for _, r := range g.config.Roles {
		if r.HasBoundary && len(r.BoundaryActions) > 0 && !HasWildcardActions(r.BoundaryActions) {
			explicit := ExpandAnalyzableActions(r.BoundaryActions)
			fate.BlockingLayer = "Layer 6 (permission boundary)"
			fate.BlockingReason = fmt.Sprintf("permission boundary restricts to [%s] only", strings.Join(explicit, ", "))
			return fate
		}
	}
	for _, u := range g.config.Users {
		if u.HasBoundary && len(u.BoundaryActions) > 0 && !HasWildcardActions(u.BoundaryActions) {
			explicit := ExpandAnalyzableActions(u.BoundaryActions)
			fate.BlockingLayer = "Layer 6 (permission boundary)"
			fate.BlockingReason = fmt.Sprintf("permission boundary restricts to [%s] only", strings.Join(explicit, ", "))
			return fate
		}
	}

	fate.EffectivelyAllow = true
	return fate
}

// addWildcardLayer appends a layer label to wildcardLayers (no duplicates).
func (g *Generator) addWildcardLayer(label string) {
	for _, l := range g.wildcardLayers {
		if l == label {
			return
		}
	}
	g.wildcardLayers = append(g.wildcardLayers, label)
}

// collectAllExplicitActionIDs returns a set of Alloy action IDs for every
// explicit (non-wildcard) S3 action mentioned anywhere in the config.
// Used to populate the model universe for NotAction cases.
func (g *Generator) collectAllExplicitActionIDs() map[string]bool {
	result := make(map[string]bool)
	add := func(actions []string) {
		for _, a := range ExpandAnalyzableActions(actions) {
			result[ActionToAlloyID(a)] = true
		}
	}
	for _, r := range g.config.Roles {
		add(r.RolePolicyActions)
		add(r.RoleDenyActions)
		add(r.RoleNotActions)
		add(r.BoundaryActions)
	}
	for _, u := range g.config.Users {
		add(u.UserPolicyActions)
		add(u.UserDenyActions)
		add(u.UserNotActions)
		add(u.BoundaryActions)
	}
	for _, p := range g.config.BucketPolicies {
		add(p.AllowActions)
		add(p.AllowNotActions)
		add(p.DenyActions)
		add(p.DenyNotActions)
	}
	for _, op := range g.config.OrgPolicies {
		add(op.AllowActions)
		add(op.AllowNotActions)
		add(op.DenyActions)
	}
	return result
}

// collectValues gathers all values (actions, tags, VPCEs) that appear in the
// config so the Alloy model's universe contains exactly the right atoms.
// Only explicitly named S3 actions are added — wildcards (s3:*) are detected
// for the wildcard note but not expanded to a hardcoded catalog.
func (g *Generator) collectValues() {
	// Always include baseline values so the Alloy model has at least one atom
	// of each required type, even for minimal configs.
	g.tags["DEV"] = true
	g.tags["PROD"] = true
	g.vpces["VPCE_OTHER"] = true

	for _, b := range g.config.Buckets {
		if b.EnvTag != "" {
			g.tags[strings.ToUpper(b.EnvTag)] = true
		}
	}

	addAction := func(a string) {
		g.actions[ActionToAlloyID(a)] = true
	}

	// For NotAction policies, add all explicit actions from the entire config
	// so Alloy can reason about which actions the NotAction exclusion covers.
	allExplicitIDs := g.collectAllExplicitActionIDs()
	addAllExplicitActions := func() {
		for id := range allExplicitIDs {
			g.actions[id] = true
		}
	}

	for _, r := range g.config.Roles {
		if r.EnvTag != "" {
			g.tags[strings.ToUpper(r.EnvTag)] = true
		}
		if HasWildcardActions(r.RolePolicyActions) {
			g.addWildcardLayer("Layer 5 (identity policy)")
		}
		for _, a := range ExpandAnalyzableActions(r.RolePolicyActions) {
			addAction(a)
		}
		for _, a := range ExpandAnalyzableActions(r.RoleDenyActions) {
			addAction(a)
		}
		if len(ExpandAnalyzableActions(r.RoleNotActions)) > 0 {
			addAllExplicitActions()
			g.addWildcardLayer("Layer 5 (identity policy)")
		}
		if HasWildcardActions(r.BoundaryActions) {
			g.addWildcardLayer("Layer 6 (permission boundary)")
		}
		for _, a := range ExpandAnalyzableActions(r.BoundaryActions) {
			addAction(a)
		}
	}

	for _, u := range g.config.Users {
		if u.EnvTag != "" {
			g.tags[strings.ToUpper(u.EnvTag)] = true
		}
		if HasWildcardActions(u.UserPolicyActions) {
			g.addWildcardLayer("Layer 5 (identity policy)")
		}
		for _, a := range ExpandAnalyzableActions(u.UserPolicyActions) {
			addAction(a)
		}
		for _, a := range ExpandAnalyzableActions(u.UserDenyActions) {
			addAction(a)
		}
		if len(ExpandAnalyzableActions(u.UserNotActions)) > 0 {
			addAllExplicitActions()
			g.addWildcardLayer("Layer 5 (identity policy)")
		}
		if HasWildcardActions(u.BoundaryActions) {
			g.addWildcardLayer("Layer 6 (permission boundary)")
		}
		for _, a := range ExpandAnalyzableActions(u.BoundaryActions) {
			addAction(a)
		}
	}

	for _, p := range g.config.BucketPolicies {
		if p.DenyVpceID != "" {
			g.vpces[VpceToAlloyID(p.DenyVpceID)] = true
		}
		if HasWildcardActions(p.AllowActions) {
			g.addWildcardLayer("Layer 4 (resource policy)")
		}
		for _, a := range ExpandAnalyzableActions(p.AllowActions) {
			addAction(a)
		}
		if len(ExpandAnalyzableActions(p.AllowNotActions)) > 0 {
			addAllExplicitActions()
		}
		for _, a := range ExpandAnalyzableActions(p.DenyActions) {
			addAction(a)
		}
		if len(ExpandAnalyzableActions(p.DenyNotActions)) > 0 {
			addAllExplicitActions()
		}
	}

	for _, op := range g.config.OrgPolicies {
		if op.IsSCP() {
			if HasWildcardActions(op.AllowActions) {
				g.addWildcardLayer("Layer 3 (SCP)")
			}
		} else {
			if HasWildcardActions(op.AllowActions) {
				g.addWildcardLayer("Layer 2 (RCP)")
			}
		}
		for _, a := range ExpandAnalyzableActions(op.AllowActions) {
			addAction(a)
		}
		if len(ExpandAnalyzableActions(op.AllowNotActions)) > 0 {
			addAllExplicitActions()
		}
		for _, a := range ExpandAnalyzableActions(op.DenyActions) {
			addAction(a)
		}
	}
}

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

// buildConfigFacts generates the body of the ConfigFacts fact block.
func (g *Generator) buildConfigFacts() string {
	var sb strings.Builder

	// ── S3 Buckets ────────────────────────────────────────────────────────
	for _, b := range g.config.Buckets {
		sig := "bucket_" + AlloyID(b.TFName)
		envTag := tagOrDefault(b.EnvTag, "TAG_DEV")
		sb.WriteString(fmt.Sprintf("  %s.envTag                = %s\n", sig, envTag))
		sb.WriteString(fmt.Sprintf("  %s.blockPublicACLs       = %s\n", sig, BoolToAlloy(b.BPABlockPublicACLs)))
		sb.WriteString(fmt.Sprintf("  %s.ignorePublicACLs      = %s\n", sig, BoolToAlloy(b.BPAIgnorePublicACLs)))
		sb.WriteString(fmt.Sprintf("  %s.blockPublicPolicy     = %s\n", sig, BoolToAlloy(b.BPABlockPublicPolicy)))
		sb.WriteString(fmt.Sprintf("  %s.restrictPublicBuckets = %s\n", sig, BoolToAlloy(b.BPARestrictPublicBuckets)))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn             = none\n\n", sig))
	}

	// ── Bucket Policies ───────────────────────────────────────────────────
	for _, p := range g.config.BucketPolicies {
		sig := "policy_" + AlloyID(p.TFName)

		bucketSig := "none"
		if p.BucketRef != "" {
			bucketName := strings.TrimPrefix(p.BucketRef, "aws_s3_bucket.")
			bucketSig = "bucket_" + AlloyID(bucketName)
		}

		denyAllExcept := "none"
		if p.DenyVpceID != "" {
			denyAllExcept = VpceToAlloyID(p.DenyVpceID)
		}

		allowPrincipal := "none"
		for _, prin := range p.AllowPrincipals {
			if sig := resolvePrincipalSig(prin, g.config); sig != "" {
				allowPrincipal = sig
				break
			}
		}

		denyPrincipal := "none"
		for _, prin := range p.DenyPrincipals {
			if sig := resolvePrincipalSig(prin, g.config); sig != "" {
				denyPrincipal = sig
				break
			}
		}

		allowAnyPrincipal := "False"
		if p.AllowAnyPrincipal {
			allowAnyPrincipal = "True"
		}

		denyAnyPrincipal := "False"
		if p.DenyAnyPrincipal {
			denyAnyPrincipal = "True"
		}

		allowBucketResource := "False"
		if p.AllowBucketResource {
			allowBucketResource = "True"
		}

		allowObjectResource := "False"
		if p.AllowObjectResource {
			allowObjectResource = "True"
		}

		denyBucketResource := "False"
		if p.DenyBucketResource {
			denyBucketResource = "True"
		}

		denyObjectResource := "False"
		if p.DenyObjectResource {
			denyObjectResource = "True"
		}

		allowActions := toAlloyActionSet(p.AllowActions)
		allowNotActions := toAlloyActionSet(p.AllowNotActions)
		denyActions := toAlloyActionSet(p.DenyActions)
		denyNotActions := toAlloyActionSet(p.DenyNotActions)

		sb.WriteString(fmt.Sprintf("  %s.bucket              = %s\n", sig, bucketSig))
		sb.WriteString(fmt.Sprintf("  %s.denyAllExcept       = %s\n", sig, denyAllExcept))
		sb.WriteString(fmt.Sprintf("  %s.allowPrincipal      = %s\n", sig, allowPrincipal))
		sb.WriteString(fmt.Sprintf("  %s.allowAnyPrincipal   = %s\n", sig, allowAnyPrincipal))
		sb.WriteString(fmt.Sprintf("  %s.allowActions        = %s\n", sig, allowActions))
		sb.WriteString(fmt.Sprintf("  %s.allowNotActions     = %s\n", sig, allowNotActions))
		sb.WriteString(fmt.Sprintf("  %s.hasAllowNotAction   = %s\n", sig, BoolToAlloy(p.HasAllowNotAction)))
		sb.WriteString(fmt.Sprintf("  %s.allowBucketResource = %s\n", sig, allowBucketResource))
		sb.WriteString(fmt.Sprintf("  %s.allowObjectResource = %s\n", sig, allowObjectResource))
		sb.WriteString(fmt.Sprintf("  %s.denyActions         = %s\n", sig, denyActions))
		sb.WriteString(fmt.Sprintf("  %s.denyNotActions      = %s\n", sig, denyNotActions))
		sb.WriteString(fmt.Sprintf("  %s.hasDenyNotAction    = %s\n", sig, BoolToAlloy(p.HasDenyNotAction)))
		sb.WriteString(fmt.Sprintf("  %s.denyPrincipal       = %s\n", sig, denyPrincipal))
		sb.WriteString(fmt.Sprintf("  %s.denyAnyPrincipal    = %s\n", sig, denyAnyPrincipal))
		sb.WriteString(fmt.Sprintf("  %s.denyBucketResource  = %s\n", sig, denyBucketResource))
		sb.WriteString(fmt.Sprintf("  %s.denyObjectResource  = %s\n", sig, denyObjectResource))
		sb.WriteString(fmt.Sprintf("  %s.abacCondition       = %s\n", sig, BoolToAlloy(p.HasABAC)))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn           = %s\n\n", sig, bucketSig))
	}

	// ── OrgRCPs ───────────────────────────────────────────────────────────
	for _, rcp := range g.config.RCPs() {
		sig := "rcp_" + AlloyID(rcp.TFName)
		allowA := toAlloyActionSet(rcp.AllowActions)
		allowNotA := toAlloyActionSet(rcp.AllowNotActions)
		denyA := toAlloyActionSet(rcp.DenyActions)
		sb.WriteString(fmt.Sprintf("  %s.rcpAllowActions    = %s\n", sig, allowA))
		sb.WriteString(fmt.Sprintf("  %s.rcpAllowNotActions = %s\n", sig, allowNotA))
		sb.WriteString(fmt.Sprintf("  %s.rcpDenyActions     = %s\n", sig, denyA))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn          = none\n\n", sig))
	}

	// ── OrgSCPs ───────────────────────────────────────────────────────────
	for _, scp := range g.config.SCPs() {
		sig := "scp_" + AlloyID(scp.TFName)
		allowA := toAlloyActionSet(scp.AllowActions)
		allowNotA := toAlloyActionSet(scp.AllowNotActions)
		denyA := toAlloyActionSet(scp.DenyActions)
		sb.WriteString(fmt.Sprintf("  %s.scpAllowActions    = %s\n", sig, allowA))
		sb.WriteString(fmt.Sprintf("  %s.scpAllowNotActions = %s\n", sig, allowNotA))
		sb.WriteString(fmt.Sprintf("  %s.scpDenyActions     = %s\n", sig, denyA))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn          = none\n\n", sig))
	}

	// ── IAM Roles ─────────────────────────────────────────────────────────
	for _, r := range g.config.Roles {
		sig := "role_" + AlloyID(r.TFName)
		envTag := tagOrDefault(r.EnvTag, "TAG_DEV")
		roleDenyActions := toAlloyActionSet(r.RoleDenyActions)
		roleNotActions := toAlloyActionSet(r.RoleNotActions)
		// Session policies are sts:AssumeRole runtime parameters — not in Terraform source.
		sessionActions := toAlloyActionSet(nil)

		sb.WriteString(fmt.Sprintf("  %s.envTag               = %s\n", sig, envTag))
		sb.WriteString(fmt.Sprintf("  %s.crossAccount         = %s\n", sig, BoolToAlloy(r.CrossAccount)))
		sb.WriteString(fmt.Sprintf("  %s.hasIdentityPolicy    = %s\n", sig, BoolToAlloy(r.HasRolePolicy)))
		sb.WriteString(fmt.Sprintf("  %s.identityAllowedOn    = %s\n", sig, g.buildIdentityAllowedOnRelation(r.IdentityAllowActionsPerBucket)))
		sb.WriteString(fmt.Sprintf("  %s.identityDenyActions  = %s\n", sig, roleDenyActions))
		sb.WriteString(fmt.Sprintf("  %s.identityNotActions   = %s\n", sig, roleNotActions))
		sb.WriteString(fmt.Sprintf("  %s.hasNotAction         = %s\n", sig, BoolToAlloy(r.HasRoleNotAction)))
		sb.WriteString(fmt.Sprintf("  %s.hasBoundary          = %s\n", sig, BoolToAlloy(r.HasBoundary)))
		sb.WriteString(fmt.Sprintf("  %s.boundaryAllowedOn    = %s\n", sig, g.buildIdentityAllowedOnRelation(r.BoundaryActionsPerBucket)))
		sb.WriteString(fmt.Sprintf("  %s.hasSessionPolicy     = %s\n", sig, BoolToAlloy(r.HasSessionPolicy)))
		sb.WriteString(fmt.Sprintf("  %s.sessionPolicyActions = %s\n", sig, sessionActions))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn            = none\n\n", sig))
	}

	// ── IAM Users ─────────────────────────────────────────────────────────
	for _, u := range g.config.Users {
		sig := "user_" + AlloyID(u.TFName)
		envTag := tagOrDefault(u.EnvTag, "TAG_DEV")
		userDenyActions := toAlloyActionSet(u.UserDenyActions)
		userNotActions := toAlloyActionSet(u.UserNotActions)

		sb.WriteString(fmt.Sprintf("  %s.envTag               = %s\n", sig, envTag))
		sb.WriteString(fmt.Sprintf("  %s.crossAccount         = %s\n", sig, BoolToAlloy(false)))
		sb.WriteString(fmt.Sprintf("  %s.hasIdentityPolicy    = %s\n", sig, BoolToAlloy(u.HasUserPolicy)))
		sb.WriteString(fmt.Sprintf("  %s.identityAllowedOn    = %s\n", sig, g.buildIdentityAllowedOnRelation(u.IdentityAllowActionsPerBucket)))
		sb.WriteString(fmt.Sprintf("  %s.identityDenyActions  = %s\n", sig, userDenyActions))
		sb.WriteString(fmt.Sprintf("  %s.identityNotActions   = %s\n", sig, userNotActions))
		sb.WriteString(fmt.Sprintf("  %s.hasNotAction         = %s\n", sig, BoolToAlloy(u.HasUserNotAction)))
		sb.WriteString(fmt.Sprintf("  %s.hasBoundary          = %s\n", sig, BoolToAlloy(u.HasBoundary)))
		sb.WriteString(fmt.Sprintf("  %s.boundaryAllowedOn    = %s\n", sig, g.buildIdentityAllowedOnRelation(u.BoundaryActionsPerBucket)))
		// Session policies are runtime sts:AssumeRole parameters; not applicable to IAM users.
		sb.WriteString(fmt.Sprintf("  %s.hasSessionPolicy     = %s\n", sig, BoolToAlloy(false)))
		sb.WriteString(fmt.Sprintf("  %s.sessionPolicyActions = %s\n", sig, toAlloyActionSet(nil)))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn            = none\n\n", sig))
	}

	// ── Service Principals ────────────────────────────────────────────────
	for _, sp := range g.config.ServicePrincipals {
		sig := "svc_" + AlloyID(sp.TFName)
		sb.WriteString(fmt.Sprintf("  %s.envTag               = TAG_DEV\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.crossAccount         = False\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.hasIdentityPolicy    = False\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.identityAllowedOn    = none -> none\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.identityDenyActions  = none\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.identityNotActions   = none\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.hasNotAction         = False\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.hasBoundary          = False\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.boundaryAllowedOn    = none -> none\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.hasSessionPolicy     = False\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.sessionPolicyActions = none\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn            = none\n\n", sig))
	}

	// ── Actions ───────────────────────────────────────────────────────────
	for _, action := range g.sortedKeys(g.actions) {
		bucketLevel, objectLevel := actionLevelFacts(action)
		sb.WriteString(fmt.Sprintf("  %s.bucketLevel = %s\n", action, bucketLevel))
		sb.WriteString(fmt.Sprintf("  %s.objectLevel = %s\n\n", action, objectLevel))
	}

	return sb.String()
}

func actionLevelFacts(action string) (bucketLevel string, objectLevel string) {
	// Bucket-level actions — resource ARN: arn:aws:s3:::bucket
	switch action {
	case
		// List / discovery
		"S3_ListBucket",
		"S3_ListBucketVersions",
		"S3_ListBucketMultipartUploads",
		// Bucket lifecycle
		"S3_CreateBucket",
		"S3_DeleteBucket",
		// Bucket policy
		"S3_GetBucketPolicy",
		"S3_PutBucketPolicy",
		"S3_DeleteBucketPolicy",
		"S3_GetBucketPolicyStatus",
		// ACL
		"S3_GetBucketAcl",
		"S3_PutBucketAcl",
		// Versioning
		"S3_GetBucketVersioning",
		"S3_PutBucketVersioning",
		// Tagging
		"S3_GetBucketTagging",
		"S3_PutBucketTagging",
		"S3_DeleteBucketTagging",
		// Encryption
		"S3_GetEncryptionConfiguration",
		"S3_PutEncryptionConfiguration",
		"S3_DeleteBucketEncryption",
		// Public access block
		"S3_GetBucketPublicAccessBlock",
		"S3_PutBucketPublicAccessBlock",
		"S3_DeletePublicAccessBlock",
		// Logging
		"S3_GetBucketLogging",
		"S3_PutBucketLogging",
		// Notification
		"S3_GetBucketNotification",
		"S3_PutBucketNotification",
		// CORS
		"S3_GetBucketCORS",
		"S3_PutBucketCORS",
		"S3_DeleteBucketCORS",
		// Website
		"S3_GetBucketWebsite",
		"S3_PutBucketWebsite",
		"S3_DeleteBucketWebsite",
		// Accelerate
		"S3_GetAccelerateConfiguration",
		"S3_PutAccelerateConfiguration",
		// Request payment
		"S3_GetBucketRequestPayment",
		"S3_PutBucketRequestPayment",
		// Replication
		"S3_GetReplicationConfiguration",
		"S3_PutReplicationConfiguration",
		"S3_DeleteBucketReplication",
		// Lifecycle
		"S3_GetLifecycleConfiguration",
		"S3_PutLifecycleConfiguration",
		"S3_DeleteBucketLifecycle",
		// Intelligent tiering
		"S3_GetIntelligentTieringConfiguration",
		"S3_PutIntelligentTieringConfiguration",
		"S3_DeleteIntelligentTieringConfiguration",
		"S3_ListBucketIntelligentTieringConfigurations",
		// Inventory
		"S3_GetInventoryConfiguration",
		"S3_PutInventoryConfiguration",
		"S3_DeleteInventoryConfiguration",
		"S3_ListBucketInventoryConfigurations",
		// Analytics
		"S3_GetAnalyticsConfiguration",
		"S3_PutAnalyticsConfiguration",
		"S3_DeleteBucketAnalyticsConfiguration",
		"S3_ListBucketAnalyticsConfigurations",
		// Metrics
		"S3_GetMetricsConfiguration",
		"S3_PutMetricsConfiguration",
		"S3_DeleteBucketMetricsConfiguration",
		"S3_ListBucketMetricsConfigurations",
		// Object lock config (bucket-level)
		"S3_GetBucketObjectLockConfiguration",
		"S3_PutBucketObjectLockConfiguration",
		// Ownership controls
		"S3_GetBucketOwnershipControls",
		"S3_PutBucketOwnershipControls",
		"S3_DeleteBucketOwnershipControls",
		// Multipart uploads listing (bucket-level)
		"S3_ListMultipartUploads",
		// Location
		"S3_GetBucketLocation":
		return "True", "False"
	}

	// Object-level actions — resource ARN: arn:aws:s3:::bucket/*
	switch action {
	case
		// Core object operations
		"S3_GetObject",
		"S3_PutObject",
		"S3_DeleteObject",
		"S3_CopyObject",
		"S3_HeadObject",
		// Versions
		"S3_GetObjectVersion",
		"S3_DeleteObjectVersion",
		"S3_CopyObjectVersion",
		// ACL
		"S3_GetObjectAcl",
		"S3_PutObjectAcl",
		"S3_GetObjectVersionAcl",
		"S3_PutObjectVersionAcl",
		// Tagging
		"S3_GetObjectTagging",
		"S3_PutObjectTagging",
		"S3_DeleteObjectTagging",
		"S3_GetObjectVersionTagging",
		"S3_PutObjectVersionTagging",
		"S3_DeleteObjectVersionTagging",
		// Attributes / metadata
		"S3_GetObjectAttributes",
		"S3_GetObjectVersionAttributes",
		// Legal hold / retention
		"S3_GetObjectLegalHold",
		"S3_PutObjectLegalHold",
		"S3_GetObjectRetention",
		"S3_PutObjectRetention",
		// Restore
		"S3_RestoreObject",
		// Multipart upload (object-level parts)
		"S3_AbortMultipartUpload",
		"S3_ListMultipartUploadParts",
		"S3_CreateMultipartUpload",
		"S3_CompleteMultipartUpload",
		"S3_UploadPart",
		"S3_UploadPartCopy",
		// Torrent
		"S3_GetObjectTorrent",
		"S3_GetObjectVersionTorrent",
		// Replication (object-level — used in replication bucket policies)
		"S3_ReplicateObject",
		"S3_ReplicateDelete",
		"S3_ReplicateTags",
		"S3_GetObjectVersionForReplication",
		"S3_InitiateReplication",
		// Object Lock governance bypass
		"S3_BypassGovernanceRetention":
		return "False", "True"
	}

	// Unknown action — resource level cannot be determined statically.
	return "False", "False"
}

// toAlloyActionSet converts a slice of IAM action strings to an Alloy set expression.
// A wildcard (e.g. s3:*) maps to the full Action universe; explicit actions are listed.
func toAlloyActionSet(actions []string) string {
	if HasWildcardActions(actions) {
		return "Action"
	}
	expanded := ExpandAnalyzableActions(actions)
	if len(expanded) == 0 {
		return "none"
	}
	ids := make([]string, 0, len(expanded))
	for _, a := range expanded {
		ids = append(ids, ActionToAlloyID(a))
	}
	return FormatAlloySet(ids)
}

// tagOrDefault converts an environment tag to its Alloy identifier,
// or returns the default when the tag is empty.
func tagOrDefault(tag, defaultTag string) string {
	if tag == "" {
		return defaultTag
	}
	return TagToAlloyID(tag)
}

func resolvePrincipalSig(principal string, config *ir.Config) string {

	for _, sp := range config.ServicePrincipals {
		if principal == sp.Name {
			return "svc_" + AlloyID(sp.TFName)
		}
	}

	// Direct Terraform reference: "aws_iam_role.name" or "aws_iam_user.name"
	if strings.HasPrefix(principal, "aws_iam_role.") {
		parts := strings.Split(principal, ".")
		if len(parts) >= 2 {
			return "role_" + AlloyID(parts[1])
		}
	}
	if strings.HasPrefix(principal, "aws_iam_user.") {
		parts := strings.Split(principal, ".")
		if len(parts) >= 2 {
			return "user_" + AlloyID(parts[1])
		}
	}

	for _, prefix := range []string{"${aws_iam_role.", "${aws_iam_user."} {
		if strings.Contains(principal, prefix) {
			start := strings.Index(principal, prefix) + len(prefix)
			end := strings.Index(principal[start:], ".")
			if end > 0 {
				name := principal[start : start+end]
				if strings.Contains(prefix, "role") {
					return "role_" + AlloyID(name)
				}
				return "user_" + AlloyID(name)
			}
		}
	}

	for _, r := range config.Roles {
		if strings.Contains(principal, r.Name) || strings.Contains(principal, r.TFName) {
			return "role_" + AlloyID(r.TFName)
		}
	}
	for _, u := range config.Users {
		if strings.Contains(principal, u.Name) || strings.Contains(principal, u.TFName) {
			return "user_" + AlloyID(u.TFName)
		}
	}
	return ""
}

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

// buildIdentityAllowedOnRelation converts the per-bucket action map from IR into an
// Alloy relation expression for the identityAllowedOn field.
// perBucketActions keys are actual S3 bucket names (from ARNs) or bucket TFNames;
// the special key "*" means actions apply to all buckets.
// A wildcard action (s3:*) maps to the full Action universe in Alloy.
func (g *Generator) buildIdentityAllowedOnRelation(perBucketActions map[string][]string) string {
	if len(perBucketActions) == 0 {
		return "none -> none"
	}

	wildcardActions := perBucketActions["*"]
	wildcardCoversAll := HasWildcardActions(wildcardActions)

	type entry struct {
		bucketSig  string
		actionExpr string
	}

	var entries []entry
	for _, b := range g.config.Buckets {
		bucketSig := "bucket_" + AlloyID(b.TFName)

		if wildcardCoversAll {
			entries = append(entries, entry{bucketSig: bucketSig, actionExpr: "Action"})
			continue
		}

		actionSet := make(map[string]bool)
		for _, a := range ExpandAnalyzableActions(wildcardActions) {
			actionSet[ActionToAlloyID(a)] = true
		}

		bucketHasWildcard := false
		for _, key := range []string{b.BucketName, b.TFName} {
			if key == "" || key == "*" {
				continue
			}
			if specific, ok := perBucketActions[key]; ok {
				if HasWildcardActions(specific) {
					bucketHasWildcard = true
					break
				}
				for _, a := range ExpandAnalyzableActions(specific) {
					actionSet[ActionToAlloyID(a)] = true
				}
			}
		}

		if bucketHasWildcard {
			entries = append(entries, entry{bucketSig: bucketSig, actionExpr: "Action"})
			continue
		}

		if len(actionSet) == 0 {
			continue
		}

		var actionIDs []string
		for id := range actionSet {
			actionIDs = append(actionIDs, id)
		}
		sort.Strings(actionIDs)
		entries = append(entries, entry{
			bucketSig:  bucketSig,
			actionExpr: FormatAlloySet(actionIDs),
		})
	}

	if len(entries) == 0 {
		return "none -> none"
	}

	parts := make([]string, len(entries))
	for i, e := range entries {
		parts[i] = fmt.Sprintf("%s -> (%s)", e.bucketSig, e.actionExpr)
	}
	return strings.Join(parts, " +\n    ")
}

func Generate(config *ir.Config, sourceFile, outputFile string) error {
	return NewGenerator(config, sourceFile).GenerateToFile(outputFile)
}

func GenerateToWriter(config *ir.Config, sourceFile string, w io.Writer) error {
	return NewGenerator(config, sourceFile).GenerateToWriter(w)
}
