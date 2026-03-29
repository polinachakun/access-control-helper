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

// Generator produces Alloy specifications from IR Config.
type Generator struct {
	config     *ir.Config
	sourceFile string

	tags    map[string]bool
	vpces   map[string]bool
	actions map[string]bool
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

// GenerateToFile writes the Alloy specification to a file.
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

// GenerateToWriter writes the Alloy specification to any io.Writer (e.g. os.Stdout).
func (g *Generator) GenerateToWriter(w io.Writer) error {
	g.collectValues()
	data := g.buildTemplateData()
	return RenderTemplate(w, data)
}

// collectValues gathers all unique tags, VPCEs, and actions.
func (g *Generator) collectValues() {
	g.tags["PROD"] = true
	g.tags["DEV"] = true
	g.vpces["VPCE_OTHER"] = true

	g.actions["S3_GetObject"] = true
	g.actions["S3_ListBucket"] = true
	g.actions["S3_Other"] = true

	for _, b := range g.config.Buckets {
		if b.EnvTag != "" {
			g.tags[strings.ToUpper(b.EnvTag)] = true
		}
	}

	for _, r := range g.config.Roles {
		if r.EnvTag != "" {
			g.tags[strings.ToUpper(r.EnvTag)] = true
		}
		for _, a := range r.RolePolicyActions {
			g.actions[ActionToAlloyID(a)] = true
		}
	}

	for _, p := range g.config.BucketPolicies {
		if p.DenyVpceID != "" {
			g.vpces[VpceToAlloyID(p.DenyVpceID)] = true
		}
		for _, a := range p.AllowActions {
			g.actions[ActionToAlloyID(a)] = true
		}
	}
}

// buildTemplateData creates the template data structure.
func (g *Generator) buildTemplateData() *TemplateData {
	data := &TemplateData{
		SourceFile: filepath.Base(g.sourceFile),
		Predicates: GeneratePredicates(),
	}

	// Tag values
	tagList := g.sortedKeys(g.tags)
	tagIDs := make([]string, len(tagList))
	for i, t := range tagList {
		tagIDs[i] = TagToAlloyID(t)
	}
	data.TagValues = strings.Join(tagIDs, ", ")

	// VPCE IDs
	data.VpceIds = g.sortedKeys(g.vpces)

	// Action values
	data.ActionValues = strings.Join(g.sortedKeys(g.actions), ", ")

	// Concrete resources
	bucketNames := make([]string, len(g.config.Buckets))
	for i, b := range g.config.Buckets {
		bucketNames[i] = AlloyID(b.TFName)
	}
	data.Buckets = bucketNames

	policyNames := make([]string, len(g.config.BucketPolicies))
	for i, p := range g.config.BucketPolicies {
		policyNames[i] = AlloyID(p.TFName)
	}
	data.BucketPolicies = policyNames

	roleNames := make([]string, len(g.config.Roles))
	for i, r := range g.config.Roles {
		roleNames[i] = AlloyID(r.TFName)
	}
	data.Roles = roleNames

	// Build unions
	data.BucketUnion = g.buildUnion(bucketNames, "bucket_")
	data.BucketPolicyUnion = g.buildUnion(policyNames, "policy_")
	data.RoleUnion = g.buildUnion(roleNames, "role_")

	// Build config facts
	data.ConfigFacts = g.buildConfigFacts()

	// Generate assertions for first bucket/policy/role pair
	bucketName := ""
	policyName := ""
	roleName := ""
	if len(bucketNames) > 0 {
		bucketName = bucketNames[0]
	}
	if len(policyNames) > 0 {
		policyName = policyNames[0]
	}
	if len(roleNames) > 0 {
		roleName = roleNames[0]
	}
	data.Assertions = GenerateAssertions(bucketName, policyName, roleName)

	// Generate access assertions for all (role, bucket, action) triples
	data.AccessAssertions = GenerateAccessAssertions(roleNames, bucketNames, g.sortedKeys(g.actions))

	// Build scope and checks
	scope := fmt.Sprintf("for exactly %d S3Bucket, exactly %d BucketPolicy, exactly %d IAMRole,\n      exactly 2 Request, exactly 2 VpceId, exactly 2 TagValue, exactly 3 Action, exactly 2 Bool",
		len(g.config.Buckets), len(g.config.BucketPolicies), len(g.config.Roles))
	data.Checks = GenerateChecks(scope, data.Assertions)

	return data
}

// buildUnion creates an Alloy union expression.
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

// buildConfigFacts generates the ConfigFacts section.
func (g *Generator) buildConfigFacts() string {
	var sb strings.Builder

	// Bucket facts
	for _, b := range g.config.Buckets {
		sig := "bucket_" + AlloyID(b.TFName)
		envTag := "TAG_DEV"
		if b.EnvTag != "" {
			envTag = TagToAlloyID(b.EnvTag)
		}
		bpa := BoolToAlloy(b.HasBPA)

		sb.WriteString(fmt.Sprintf("  %s.envTag            = %s\n", sig, envTag))
		sb.WriteString(fmt.Sprintf("  %s.blockPublicAccess = %s\n", sig, bpa))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn         = none\n\n", sig))
	}

	// Bucket policy facts
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
		if len(p.AllowPrincipals) > 0 {
			for _, prin := range p.AllowPrincipals {
				if roleRef := extractRoleFromPrincipal(prin, g.config); roleRef != "" {
					allowPrincipal = "role_" + AlloyID(roleRef)
					break
				}
			}
		}

		allowActions := "none"
		if len(p.AllowActions) > 0 {
			actionIDs := make([]string, 0, len(p.AllowActions))
			for _, a := range p.AllowActions {
				actionIDs = append(actionIDs, ActionToAlloyID(a))
			}
			allowActions = actionsToAlloySet(actionIDs)
		}

		denyActions := "none"
		if len(p.DenyActions) > 0 {
			actionIDs := make([]string, 0, len(p.DenyActions))
			for _, a := range p.DenyActions {
				actionIDs = append(actionIDs, ActionToAlloyID(a))
			}
			denyActions = actionsToAlloySet(actionIDs)
		}

		denyPrincipal := "none"
		if len(p.DenyPrincipals) > 0 {
			for _, prin := range p.DenyPrincipals {
				if roleRef := extractRoleFromPrincipal(prin, g.config); roleRef != "" {
					denyPrincipal = "role_" + AlloyID(roleRef)
					break
				}
			}
		}

		abacCondition := BoolToAlloy(p.HasABAC)

		sb.WriteString(fmt.Sprintf("  %s.bucket         = %s\n", sig, bucketSig))
		sb.WriteString(fmt.Sprintf("  %s.denyAllExcept  = %s\n", sig, denyAllExcept))
		sb.WriteString(fmt.Sprintf("  %s.allowPrincipal = %s\n", sig, allowPrincipal))
		sb.WriteString(fmt.Sprintf("  %s.allowActions   = %s\n", sig, allowActions))
		sb.WriteString(fmt.Sprintf("  %s.denyActions    = %s\n", sig, denyActions))
		sb.WriteString(fmt.Sprintf("  %s.denyPrincipal = %s\n", sig, denyPrincipal))
		sb.WriteString(fmt.Sprintf("  %s.abacCondition  = %s\n", sig, abacCondition))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn      = %s\n\n", sig, bucketSig))
	}

	// Role facts
	for _, r := range g.config.Roles {
		sig := "role_" + AlloyID(r.TFName)
		envTag := "TAG_DEV"
		if r.EnvTag != "" {
			envTag = TagToAlloyID(r.EnvTag)
		}

		hasRolePolicy := BoolToAlloy(r.HasRolePolicy)
		roleAllowActions := "none"
		if len(r.RolePolicyActions) > 0 {
			actionIDs := make([]string, 0, len(r.RolePolicyActions))
			for _, a := range r.RolePolicyActions {
				actionIDs = append(actionIDs, ActionToAlloyID(a))
			}
			roleAllowActions = actionsToAlloySet(actionIDs)
		}

		sb.WriteString(fmt.Sprintf("  %s.envTag           = %s\n", sig, envTag))
		sb.WriteString(fmt.Sprintf("  %s.hasRolePolicy    = %s\n", sig, hasRolePolicy))
		sb.WriteString(fmt.Sprintf("  %s.roleAllowActions = %s\n", sig, roleAllowActions))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn        = none\n\n", sig))
	}

	return sb.String()
}

// actionsToAlloySet converts action IDs to an Alloy set expression.
// If any action is a wildcard (ends in "_All"), returns "Action" — the full universe.
func actionsToAlloySet(actionIDs []string) string {
	for _, id := range actionIDs {
		if strings.HasSuffix(id, "_All") {
			return "Action"
		}
	}
	return FormatAlloySet(actionIDs)
}

// sortedKeys returns sorted keys from a map.
func (g *Generator) sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// extractRoleFromPrincipal tries to find a matching role for a principal ARN.
func extractRoleFromPrincipal(principal string, config *ir.Config) string {
	if strings.HasPrefix(principal, "aws_iam_role.") {
		parts := strings.Split(principal, ".")
		if len(parts) >= 2 {
			return parts[1]
		}
	}

	for _, r := range config.Roles {
		if strings.Contains(principal, r.Name) || strings.Contains(principal, r.TFName) {
			return r.TFName
		}
	}

	if strings.Contains(principal, "${aws_iam_role.") {
		start := strings.Index(principal, "${aws_iam_role.") + len("${aws_iam_role.")
		end := strings.Index(principal[start:], ".")
		if end > 0 {
			return principal[start : start+end]
		}
	}

	return ""
}

// Generate is a convenience function that creates a generator and generates output.
func Generate(config *ir.Config, sourceFile, outputFile string) error {
	gen := NewGenerator(config, sourceFile)
	return gen.GenerateToFile(outputFile)
}

// GenerateToWriter is a convenience function that writes to any io.Writer.
func GenerateToWriter(config *ir.Config, sourceFile string, w io.Writer) error {
	gen := NewGenerator(config, sourceFile)
	return gen.GenerateToWriter(w)
}

// GenerateAccessAssertions creates assertions for every (role, bucket, action) triple.
func GenerateAccessAssertions(roleNames, bucketNames, actionNames []string) []Assertion {
	assertions := []Assertion{}
	for _, role := range roleNames {
		for _, bucket := range bucketNames {
			for _, action := range actionNames {
				assertionName := fmt.Sprintf("%sCan%sOn%s",
					strings.Title(strings.ReplaceAll(role, "_", "")),
					strings.Title(strings.ReplaceAll(strings.TrimPrefix(action, "S3_"), "_", "")),
					strings.Title(strings.ReplaceAll(bucket, "_", "")),
				)
				comment := fmt.Sprintf("Checks if %s can %s on %s.", role, action, bucket)
				body := fmt.Sprintf(`some req: Request |
    req.principal = role_%s and
    req.action = %s and
    req.target = bucket_%s
    implies accessAllowed[req]`, role, action, bucket)
				assertions = append(assertions, Assertion{
					Name:    assertionName,
					Comment: comment,
					Body:    body,
				})
			}
		}
	}
	return assertions
}
