package ir

import (
	"regexp"
	"strings"

	"access-control-helper/internal/resolver"
)

func (b *Builder) getAttrAsString(res *resolver.ResolvedResource, name string) string {
	if val, ok := res.Attributes[name]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

func (b *Builder) getAttrAsBool(res *resolver.ResolvedResource, name string) bool {
	if val, ok := res.Attributes[name]; ok {
		if bv, ok := val.(bool); ok {
			return bv
		}
	}
	return false
}

func (b *Builder) getAttrAsMap(res *resolver.ResolvedResource, name string) map[string]string {
	if val, ok := res.Attributes[name]; ok {
		if m, ok := val.(map[string]interface{}); ok {
			result := make(map[string]string)
			for k, v := range m {
				if s, ok := v.(string); ok {
					result[k] = s
				}
			}
			return result
		}
	}
	return nil
}

// looksLikeUnresolvedRef returns true when s is not valid JSON because it
// contains Terraform variable/resource references that were not evaluated.
// Examples: `data.aws_iam_policy_document.x.json`, `aws_iam_role.x.arn`,
// or any JSON-like string containing `${...}` template expressions.
func looksLikeUnresolvedRef(s string) bool {
	if strings.Contains(s, "${") {
		return true
	}
	if strings.HasPrefix(s, "data.") || strings.HasPrefix(s, "var.") || strings.HasPrefix(s, "local.") {
		return true
	}
	if strings.HasPrefix(s, "aws_") {
		return true
	}
	return false
}

// extractResourceRef extracts a resource reference from various formats.
func extractResourceRef(s string) string {
	re := regexp.MustCompile(`(aws_[a-z0-9_]+)\.([a-z0-9_]+)`)
	matches := re.FindStringSubmatch(s)
	if len(matches) >= 3 {
		return matches[1] + "." + matches[2]
	}
	return ""
}

// mergePerBucketActions merges src into dst, deduplicating actions per bucket key.
func mergePerBucketActions(dst, src map[string][]string) {
	for bucket, actions := range src {
		seen := make(map[string]bool, len(dst[bucket]))
		for _, a := range dst[bucket] {
			seen[a] = true
		}
		for _, a := range actions {
			if !seen[a] {
				seen[a] = true
				dst[bucket] = append(dst[bucket], a)
			}
		}
	}
}
