package generator

import "strings"

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
