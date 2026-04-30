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

	principals  []PrincipalEntry
	bucketNames []string
	actionNames []string
}

// NewGenerator creates a new Generator.
func NewGenerator(config *ir.Config, sourceFile string) *Generator {
	return &Generator{
		config:     config,
		sourceFile: sourceFile,
		tags:       make(map[string]bool),
		vpces:      make(map[string]bool),
		actions:    make(map[string]bool),
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

// Important: wildcard policy actions like "s3:*" are expanded into
// analyzable concrete actions via ExpandAnalyzableActions(...),
// so they do not appear in reports as synthetic actions like "S3_All".
func (g *Generator) collectValues() {
	// Always include baseline values so the Alloy model has at least one atom
	// of each required type, even for minimal configs.
	g.tags["DEV"] = true
	g.tags["PROD"] = true
	g.vpces["VPCE_OTHER"] = true

	for _, actions := range SupportedActionsByService {
		for _, a := range actions {
			g.actions[ActionToAlloyID(a)] = true
		}
	}

	for _, b := range g.config.Buckets {
		if b.EnvTag != "" {
			g.tags[strings.ToUpper(b.EnvTag)] = true
		}
	}

	for _, r := range g.config.Roles {
		if r.EnvTag != "" {
			g.tags[strings.ToUpper(r.EnvTag)] = true
		}
		for _, a := range ExpandAnalyzableActions(r.RolePolicyActions) {
			g.actions[ActionToAlloyID(a)] = true
		}
		for _, a := range ExpandAnalyzableActions(r.RoleDenyActions) {
			g.actions[ActionToAlloyID(a)] = true
		}
		for _, a := range ExpandAnalyzableActions(r.RoleNotActions) {
			g.actions[ActionToAlloyID(a)] = true
		}
		for _, a := range ExpandAnalyzableActions(r.BoundaryActions) {
			g.actions[ActionToAlloyID(a)] = true
		}
	}

	for _, u := range g.config.Users {
		if u.EnvTag != "" {
			g.tags[strings.ToUpper(u.EnvTag)] = true
		}
		for _, a := range ExpandAnalyzableActions(u.UserPolicyActions) {
			g.actions[ActionToAlloyID(a)] = true
		}
		for _, a := range ExpandAnalyzableActions(u.UserDenyActions) {
			g.actions[ActionToAlloyID(a)] = true
		}
		for _, a := range ExpandAnalyzableActions(u.UserNotActions) {
			g.actions[ActionToAlloyID(a)] = true
		}
		for _, a := range ExpandAnalyzableActions(u.BoundaryActions) {
			g.actions[ActionToAlloyID(a)] = true
		}
	}

	for _, p := range g.config.BucketPolicies {
		if p.DenyVpceID != "" {
			g.vpces[VpceToAlloyID(p.DenyVpceID)] = true
		}

		for _, a := range ExpandAnalyzableActions(p.AllowActions) {
			g.actions[ActionToAlloyID(a)] = true
		}
		for _, a := range ExpandAnalyzableActions(p.AllowNotActions) {
			g.actions[ActionToAlloyID(a)] = true
		}
		for _, a := range ExpandAnalyzableActions(p.DenyActions) {
			g.actions[ActionToAlloyID(a)] = true
		}
		for _, a := range ExpandAnalyzableActions(p.DenyNotActions) {
			g.actions[ActionToAlloyID(a)] = true
		}
	}

	for _, op := range g.config.OrgPolicies {
		for _, a := range ExpandAnalyzableActions(op.AllowActions) {
			g.actions[ActionToAlloyID(a)] = true
		}
		for _, a := range ExpandAnalyzableActions(op.DenyActions) {
			g.actions[ActionToAlloyID(a)] = true
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
		bucketNames[i] = AlloyID(b.TFName)
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
		roleNames[i] = AlloyID(r.TFName)
	}
	data.Roles = roleNames
	data.RoleUnion = g.buildUnion(roleNames, "role_")

	// ── IAM Users ─────────────────────────────────────────────────────────
	userNames := make([]string, len(g.config.Users))
	for i, u := range g.config.Users {
		userNames[i] = AlloyID(u.TFName)
	}
	data.Users = userNames
	data.UserUnion = g.buildUnion(userNames, "user_")

	// ── Config facts ──────────────────────────────────────────────────────
	data.ConfigFacts = g.buildConfigFacts()

	// ── Build principals list for TripleMetadata() and assertions ─────────
	sortedActions := g.sortedKeys(g.actions)
	principals := make([]PrincipalEntry, 0, len(roleNames)+len(userNames))
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
	requestCount := (len(g.config.Roles) + len(g.config.Users)) * len(g.config.Buckets) * actionCount
	if requestCount < 1 {
		requestCount = 1
	}

	scope := fmt.Sprintf(
		"for exactly %d S3Bucket, exactly %d BucketPolicy,\n"+
			"      exactly %d OrgRCP, exactly %d OrgSCP,\n"+
			"      exactly %d IAMRole, exactly %d IAMUser, exactly %d Request,\n"+
			"      exactly %d VpceId, exactly %d TagValue,\n"+
			"      exactly %d Action, exactly 2 Bool",
		len(g.config.Buckets), len(g.config.BucketPolicies),
		len(rcps), len(scps),
		len(g.config.Roles), len(g.config.Users), requestCount,
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
		sb.WriteString(fmt.Sprintf("  %s.envTag            = %s\n", sig, envTag))
		sb.WriteString(fmt.Sprintf("  %s.blockPublicAccess = %s\n", sig, BoolToAlloy(b.HasBPA)))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn         = none\n\n", sig))
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
			if ref := extractRoleFromPrincipal(prin, g.config); ref != "" {
				allowPrincipal = "role_" + AlloyID(ref)
				break
			}
		}

		denyPrincipal := "none"
		for _, prin := range p.DenyPrincipals {
			if ref := extractRoleFromPrincipal(prin, g.config); ref != "" {
				denyPrincipal = "role_" + AlloyID(ref)
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
		denyA := toAlloyActionSet(rcp.DenyActions)
		sb.WriteString(fmt.Sprintf("  %s.rcpAllowActions = %s\n", sig, allowA))
		sb.WriteString(fmt.Sprintf("  %s.rcpDenyActions  = %s\n", sig, denyA))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn       = none\n\n", sig))
	}

	// ── OrgSCPs ───────────────────────────────────────────────────────────
	for _, scp := range g.config.SCPs() {
		sig := "scp_" + AlloyID(scp.TFName)
		allowA := toAlloyActionSet(scp.AllowActions)
		denyA := toAlloyActionSet(scp.DenyActions)
		sb.WriteString(fmt.Sprintf("  %s.scpAllowActions = %s\n", sig, allowA))
		sb.WriteString(fmt.Sprintf("  %s.scpDenyActions  = %s\n", sig, denyA))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn       = none\n\n", sig))
	}

	// ── IAM Roles ─────────────────────────────────────────────────────────
	for _, r := range g.config.Roles {
		sig := "role_" + AlloyID(r.TFName)
		envTag := tagOrDefault(r.EnvTag, "TAG_DEV")
		roleActions := toAlloyActionSet(r.RolePolicyActions)
		roleDenyActions := toAlloyActionSet(r.RoleDenyActions)
		roleNotActions := toAlloyActionSet(r.RoleNotActions)
		boundaryActions := toAlloyActionSet(r.BoundaryActions)
		// Session policies are sts:AssumeRole runtime parameters — not in Terraform source.
		// HasSessionPolicy stays false; L7 is always NOT APPLICABLE for static analysis.
		sessionActions := toAlloyActionSet(nil)

		sb.WriteString(fmt.Sprintf("  %s.envTag               = %s\n", sig, envTag))
		sb.WriteString(fmt.Sprintf("  %s.crossAccount         = %s\n", sig, BoolToAlloy(r.CrossAccount)))
		sb.WriteString(fmt.Sprintf("  %s.hasIdentityPolicy    = %s\n", sig, BoolToAlloy(r.HasRolePolicy)))
		sb.WriteString(fmt.Sprintf("  %s.identityAllowActions = %s\n", sig, roleActions))
		sb.WriteString(fmt.Sprintf("  %s.identityDenyActions  = %s\n", sig, roleDenyActions))
		sb.WriteString(fmt.Sprintf("  %s.identityNotActions   = %s\n", sig, roleNotActions))
		sb.WriteString(fmt.Sprintf("  %s.hasNotAction         = %s\n", sig, BoolToAlloy(r.HasRoleNotAction)))
		sb.WriteString(fmt.Sprintf("  %s.hasBoundary          = %s\n", sig, BoolToAlloy(r.HasBoundary)))
		sb.WriteString(fmt.Sprintf("  %s.boundaryActions      = %s\n", sig, boundaryActions))
		sb.WriteString(fmt.Sprintf("  %s.hasSessionPolicy     = %s\n", sig, BoolToAlloy(r.HasSessionPolicy)))
		sb.WriteString(fmt.Sprintf("  %s.sessionPolicyActions = %s\n", sig, sessionActions))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn            = none\n\n", sig))
	}

	// ── IAM Users ─────────────────────────────────────────────────────────
	for _, u := range g.config.Users {
		sig := "user_" + AlloyID(u.TFName)
		envTag := tagOrDefault(u.EnvTag, "TAG_DEV")
		userActions := toAlloyActionSet(u.UserPolicyActions)
		userDenyActions := toAlloyActionSet(u.UserDenyActions)
		userNotActions := toAlloyActionSet(u.UserNotActions)
		boundaryActions := toAlloyActionSet(u.BoundaryActions)

		sb.WriteString(fmt.Sprintf("  %s.envTag               = %s\n", sig, envTag))
		sb.WriteString(fmt.Sprintf("  %s.crossAccount         = %s\n", sig, BoolToAlloy(false)))
		sb.WriteString(fmt.Sprintf("  %s.hasIdentityPolicy    = %s\n", sig, BoolToAlloy(u.HasUserPolicy)))
		sb.WriteString(fmt.Sprintf("  %s.identityAllowActions = %s\n", sig, userActions))
		sb.WriteString(fmt.Sprintf("  %s.identityDenyActions  = %s\n", sig, userDenyActions))
		sb.WriteString(fmt.Sprintf("  %s.identityNotActions   = %s\n", sig, userNotActions))
		sb.WriteString(fmt.Sprintf("  %s.hasNotAction         = %s\n", sig, BoolToAlloy(u.HasUserNotAction)))
		sb.WriteString(fmt.Sprintf("  %s.hasBoundary          = %s\n", sig, BoolToAlloy(u.HasBoundary)))
		sb.WriteString(fmt.Sprintf("  %s.boundaryActions      = %s\n", sig, boundaryActions))
		// Session policies are runtime sts:AssumeRole parameters; not applicable to IAM users.
		sb.WriteString(fmt.Sprintf("  %s.hasSessionPolicy     = %s\n", sig, BoolToAlloy(false)))
		sb.WriteString(fmt.Sprintf("  %s.sessionPolicyActions = %s\n", sig, toAlloyActionSet(nil)))
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

// ── Helpers ───────────────────────────────────────────────────────────────────

func actionLevelFacts(action string) (bucketLevel string, objectLevel string) {
	switch action {
	case "S3_ListBucket":
		return "True", "False"
	case "S3_GetObject", "S3_PutObject", "S3_DeleteObject":
		return "False", "True"
	default:
		return "False", "False"
	}
}

// toAlloyActionSet converts a slice of IAM action strings to an Alloy set expression.
// If any action is a wildcard (s3:*), returns "Action" (the full universe).
func toAlloyActionSet(actions []string) string {
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

// extractRoleFromPrincipal resolves a principal ARN/reference to an IAM role TFName.
func extractRoleFromPrincipal(principal string, config *ir.Config) string {
	// Direct Terraform reference: "aws_iam_role.name"
	if strings.HasPrefix(principal, "aws_iam_role.") {
		parts := strings.Split(principal, ".")
		if len(parts) >= 2 {
			return parts[1]
		}
	}

	if strings.Contains(principal, "${aws_iam_role.") {
		start := strings.Index(principal, "${aws_iam_role.") + len("${aws_iam_role.")
		end := strings.Index(principal[start:], ".")
		if end > 0 {
			return principal[start : start+end]
		}
	}
	for _, r := range config.Roles {
		if strings.Contains(principal, r.Name) || strings.Contains(principal, r.TFName) {
			return r.TFName
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
	return BuildTripleKeysFromPrincipals(g.principals, g.bucketNames, g.actionNames)
}

func Generate(config *ir.Config, sourceFile, outputFile string) error {
	return NewGenerator(config, sourceFile).GenerateToFile(outputFile)
}

func GenerateToWriter(config *ir.Config, sourceFile string, w io.Writer) error {
	return NewGenerator(config, sourceFile).GenerateToWriter(w)
}
