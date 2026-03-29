// Package evaluator implements the AWS S3 seven-layer policy evaluation logic in Go.
// It mirrors the predicates generated in the Alloy specification so that the two
// analyses can cross-verify each other: the Go evaluator produces the human-readable
// per-layer report, and the Alloy model checker formally verifies the same assertions.
package evaluator

import (
	"fmt"
	"sort"
	"strings"

	"access-control-helper/internal/ir"
)

// Decision is the final access decision for a (principal, bucket, action) triple.
type Decision int

const (
	DecisionAllow Decision = iota
	DecisionDeny
)

func (d Decision) String() string {
	if d == DecisionAllow {
		return "ALLOW"
	}
	return "DENY"
}

// LayerStatus records whether one evaluation layer passed or was denied.
type LayerStatus int

const (
	LayerPass LayerStatus = iota
	LayerDeny
	LayerNA // not applicable (e.g. no bucket policy for Layer 4)
)

func (s LayerStatus) String() string {
	switch s {
	case LayerPass:
		return "PASS"
	case LayerDeny:
		return "DENY"
	default:
		return "N/A"
	}
}

// LayerResult holds the outcome of evaluating a single policy layer.
type LayerResult struct {
	Layer  int
	Name   string
	Status LayerStatus
	Reason string
}

// EvaluationResult is the complete result for one (principal, bucket, action) triple.
type EvaluationResult struct {
	PrincipalName string
	BucketName    string
	Action        string
	Final         Decision
	DeniedAtLayer int    // 0 when allowed, 1–7 when denied
	DeniedReason  string // human-readable reason for the denial
	Layers        [7]LayerResult
}

// Evaluator walks the AWS 7-layer evaluation order for every
// (IAMRole, S3Bucket, action) triple found in an IR Config.
type Evaluator struct {
	config *ir.Config
}

// New creates a new Evaluator for the given IR Config.
func New(config *ir.Config) *Evaluator {
	return &Evaluator{config: config}
}

// EvaluateAll evaluates every (role, bucket, action) triple in the config.
func (e *Evaluator) EvaluateAll() []*EvaluationResult {
	actions := e.collectActions()
	var results []*EvaluationResult
	for _, role := range e.config.Roles {
		for _, bucket := range e.config.Buckets {
			for _, action := range actions {
				results = append(results, e.Evaluate(role, bucket, action))
			}
		}
	}
	return results
}

// Evaluate runs the 7-layer evaluation for one (role, bucket, action) triple.
func (e *Evaluator) Evaluate(role *ir.IAMRole, bucket *ir.S3Bucket, action string) *EvaluationResult {
	res := &EvaluationResult{
		PrincipalName: roleName(role),
		BucketName:    bucket.TFName,
		Action:        action,
	}

	// ── Layer 1: Explicit Deny ────────────────────────────────────────────
	l1 := e.layer1ExplicitDeny(role, bucket, action)
	res.Layers[0] = l1
	if l1.Status == LayerDeny {
		res.Final = DecisionDeny
		res.DeniedAtLayer = 1
		res.DeniedReason = l1.Reason
		return res
	}

	// ── Layer 2: RCP ──────────────────────────────────────────────────────
	l2 := e.layer2RCP(action)
	res.Layers[1] = l2
	if l2.Status == LayerDeny {
		res.Final = DecisionDeny
		res.DeniedAtLayer = 2
		res.DeniedReason = l2.Reason
		return res
	}

	// ── Layer 3: SCP ──────────────────────────────────────────────────────
	l3 := e.layer3SCP(action)
	res.Layers[2] = l3
	if l3.Status == LayerDeny {
		res.Final = DecisionDeny
		res.DeniedAtLayer = 3
		res.DeniedReason = l3.Reason
		return res
	}

	// ── Layers 4 + 5: resource policy OR identity policy must allow ────────
	l4 := e.layer4ResourcePolicy(role, bucket, action)
	l5 := e.layer5IdentityPolicy(role, action)
	res.Layers[3] = l4
	res.Layers[4] = l5

	if l4.Status != LayerPass && l5.Status != LayerPass {
		// Neither layer allows — pick the more informative denial layer.
		if e.hasBucketPolicyForBucket(bucket) {
			res.Final = DecisionDeny
			res.DeniedAtLayer = 4
			res.DeniedReason = l4.Reason
		} else {
			res.Final = DecisionDeny
			res.DeniedAtLayer = 5
			res.DeniedReason = l5.Reason
		}
		return res
	}

	// ── Layer 6: Permission Boundary ─────────────────────────────────────
	l6 := e.layer6PermBoundary(role, action)
	res.Layers[5] = l6
	if l6.Status == LayerDeny {
		res.Final = DecisionDeny
		res.DeniedAtLayer = 6
		res.DeniedReason = l6.Reason
		return res
	}

	// ── Layer 7: Session Policy ───────────────────────────────────────────
	l7 := e.layer7SessionPolicy(role, action)
	res.Layers[6] = l7
	if l7.Status == LayerDeny {
		res.Final = DecisionDeny
		res.DeniedAtLayer = 7
		res.DeniedReason = l7.Reason
		return res
	}

	res.Final = DecisionAllow
	return res
}

// ── Layer implementations ─────────────────────────────────────────────────────

func (e *Evaluator) layer1ExplicitDeny(role *ir.IAMRole, bucket *ir.S3Bucket, action string) LayerResult {
	lr := LayerResult{Layer: 1, Name: "Explicit Deny"}

	// Check every bucket policy attached to the target bucket.
	for _, bp := range e.config.BucketPolicies {
		if !e.bucketPolicyForBucket(bp, bucket) || bp.Policy == nil {
			continue
		}
		for _, stmt := range bp.Policy.Statements {
			if !stmt.IsDeny() {
				continue
			}
			if e.actionMatches(action, stmt.Actions) && e.principalMatches(role, stmt) {
				lr.Status = LayerDeny
				lr.Reason = fmt.Sprintf("explicit Deny in bucket policy %q (Sid=%q) for action %s",
					bp.TFName, stmt.SID, action)
				return lr
			}
		}
	}

	// Check inline role policies for explicit denies.
	for _, rp := range e.config.RolePolicies {
		if !e.rolePolicyForRole(rp, role) || rp.Policy == nil {
			continue
		}
		for _, stmt := range rp.Policy.Statements {
			if stmt.IsDeny() && e.actionMatches(action, stmt.Actions) {
				lr.Status = LayerDeny
				lr.Reason = fmt.Sprintf("explicit Deny in role policy %q for action %s", rp.TFName, action)
				return lr
			}
		}
	}

	lr.Status = LayerPass
	lr.Reason = "no explicit Deny found"
	return lr
}

func (e *Evaluator) layer2RCP(action string) LayerResult {
	lr := LayerResult{Layer: 2, Name: "RCP (Resource Control Policy)"}
	rcps := e.config.RCPs()
	if len(rcps) == 0 {
		lr.Status = LayerPass
		lr.Reason = "no RCPs configured — pass-through"
		return lr
	}
	for _, rcp := range rcps {
		if !e.actionInList(action, rcp.AllowActions) {
			lr.Status = LayerDeny
			lr.Reason = fmt.Sprintf("RCP %q does not allow %s", rcp.Name, action)
			return lr
		}
		if e.actionInList(action, rcp.DenyActions) {
			lr.Status = LayerDeny
			lr.Reason = fmt.Sprintf("RCP %q explicitly denies %s", rcp.Name, action)
			return lr
		}
	}
	lr.Status = LayerPass
	lr.Reason = "all RCPs allow the action"
	return lr
}

func (e *Evaluator) layer3SCP(action string) LayerResult {
	lr := LayerResult{Layer: 3, Name: "SCP (Service Control Policy)"}
	scps := e.config.SCPs()
	if len(scps) == 0 {
		lr.Status = LayerPass
		lr.Reason = "no SCPs configured — pass-through"
		return lr
	}
	for _, scp := range scps {
		if !e.actionInList(action, scp.AllowActions) {
			lr.Status = LayerDeny
			lr.Reason = fmt.Sprintf("SCP %q does not allow %s", scp.Name, action)
			return lr
		}
		if e.actionInList(action, scp.DenyActions) {
			lr.Status = LayerDeny
			lr.Reason = fmt.Sprintf("SCP %q explicitly denies %s", scp.Name, action)
			return lr
		}
	}
	lr.Status = LayerPass
	lr.Reason = "all SCPs allow the action"
	return lr
}

func (e *Evaluator) layer4ResourcePolicy(role *ir.IAMRole, bucket *ir.S3Bucket, action string) LayerResult {
	lr := LayerResult{Layer: 4, Name: "Resource Policy (Bucket Policy)"}

	for _, bp := range e.config.BucketPolicies {
		if !e.bucketPolicyForBucket(bp, bucket) || bp.Policy == nil {
			continue
		}
		for _, stmt := range bp.Policy.Statements {
			if !stmt.IsAllow() {
				continue
			}
			if e.actionMatches(action, stmt.Actions) && e.principalMatches(role, stmt) {
				lr.Status = LayerPass
				lr.Reason = fmt.Sprintf("bucket policy %q allows %s for principal %q",
					bp.TFName, action, roleName(role))
				return lr
			}
		}
	}

	if e.hasBucketPolicyForBucket(bucket) {
		lr.Status = LayerDeny
		lr.Reason = fmt.Sprintf("bucket policy does not allow %s for principal %q", action, roleName(role))
	} else {
		lr.Status = LayerNA
		lr.Reason = "no bucket policy — Layer 4 not applicable"
	}
	return lr
}

func (e *Evaluator) layer5IdentityPolicy(role *ir.IAMRole, action string) LayerResult {
	lr := LayerResult{Layer: 5, Name: "Identity Policy"}

	if !role.HasRolePolicy {
		lr.Status = LayerDeny
		lr.Reason = fmt.Sprintf("role %q has no identity policy attached", roleName(role))
		return lr
	}

	// Check role policy actions (set by inline policies and attachments).
	if e.actionInList(action, role.RolePolicyActions) {
		lr.Status = LayerPass
		lr.Reason = fmt.Sprintf("identity policy allows %s", action)
		return lr
	}

	// Also walk inline role policy documents for full statement-level matching.
	for _, rp := range e.config.RolePolicies {
		if !e.rolePolicyForRole(rp, role) || rp.Policy == nil {
			continue
		}
		for _, stmt := range rp.Policy.Statements {
			if stmt.IsAllow() && e.actionMatches(action, stmt.Actions) {
				lr.Status = LayerPass
				lr.Reason = fmt.Sprintf("inline role policy %q allows %s", rp.TFName, action)
				return lr
			}
		}
	}

	lr.Status = LayerDeny
	lr.Reason = fmt.Sprintf("no identity policy allows %s for role %q", action, roleName(role))
	return lr
}

func (e *Evaluator) layer6PermBoundary(role *ir.IAMRole, action string) LayerResult {
	lr := LayerResult{Layer: 6, Name: "Permission Boundary"}

	if !role.HasBoundary {
		lr.Status = LayerPass
		lr.Reason = "no permission boundary set — pass-through"
		return lr
	}

	if e.actionInList(action, role.BoundaryActions) {
		lr.Status = LayerPass
		lr.Reason = fmt.Sprintf("permission boundary allows %s", action)
		return lr
	}

	lr.Status = LayerDeny
	lr.Reason = fmt.Sprintf("permission boundary for role %q does not allow %s",
		roleName(role), action)
	return lr
}

func (e *Evaluator) layer7SessionPolicy(role *ir.IAMRole, action string) LayerResult {
	lr := LayerResult{Layer: 7, Name: "Session Policy"}

	if !role.HasSessionPolicy {
		lr.Status = LayerPass
		lr.Reason = "no session policy — pass-through"
		return lr
	}

	// Session policy actions are not yet extracted by the parser (Phase 3).
	// For now, treat the presence of a session policy as restricting to nothing.
	lr.Status = LayerDeny
	lr.Reason = fmt.Sprintf("session policy on role %q does not allow %s (session policy parsing is Phase 3)",
		roleName(role), action)
	return lr
}

// ── Matching helpers ──────────────────────────────────────────────────────────

// actionMatches returns true if action matches any entry in the list.
// Handles s3:*, s3:Get*, and exact matches (case-insensitive).
func (e *Evaluator) actionMatches(action string, list []string) bool {
	actionLower := strings.ToLower(action)
	for _, a := range list {
		al := strings.ToLower(a)
		if al == "*" || al == actionLower {
			return true
		}
		// Service-level wildcard: "s3:*"
		if strings.HasSuffix(al, ":*") {
			prefix := strings.TrimSuffix(al, "*")
			if strings.HasPrefix(actionLower, prefix) {
				return true
			}
		}
		// Prefix wildcard: "s3:Get*"
		if strings.HasSuffix(al, "*") {
			prefix := strings.TrimSuffix(al, "*")
			if strings.HasPrefix(actionLower, prefix) {
				return true
			}
		}
	}
	return false
}

// actionInList checks if action is in the list, handling wildcards.
func (e *Evaluator) actionInList(action string, list []string) bool {
	return e.actionMatches(action, list)
}

// principalMatches returns true if the role matches any principal in the statement.
func (e *Evaluator) principalMatches(role *ir.IAMRole, stmt *ir.Statement) bool {
	for _, p := range stmt.Principals {
		if p.Type == "*" || p.Value == "*" {
			return true
		}
		v := p.Value
		if strings.Contains(v, role.TFName) || strings.Contains(v, role.Name) {
			return true
		}
		// Terraform interpolation: "${aws_iam_role.name.arn}"
		if strings.Contains(v, "aws_iam_role."+role.TFName) {
			return true
		}
	}
	return false
}

// bucketPolicyForBucket returns true if bp is attached to bucket.
func (e *Evaluator) bucketPolicyForBucket(bp *ir.BucketPolicy, bucket *ir.S3Bucket) bool {
	if bp.BucketRef == "" {
		return false
	}
	name := strings.TrimPrefix(bp.BucketRef, "aws_s3_bucket.")
	return name == bucket.TFName
}

// hasBucketPolicyForBucket returns true if any bucket policy is attached to bucket.
func (e *Evaluator) hasBucketPolicyForBucket(bucket *ir.S3Bucket) bool {
	for _, bp := range e.config.BucketPolicies {
		if e.bucketPolicyForBucket(bp, bucket) {
			return true
		}
	}
	return false
}

// rolePolicyForRole returns true if rp is attached to role.
func (e *Evaluator) rolePolicyForRole(rp *ir.RolePolicy, role *ir.IAMRole) bool {
	if rp.RoleRef == "" {
		return false
	}
	name := strings.TrimPrefix(rp.RoleRef, "aws_iam_role.")
	return name == role.TFName
}

// ── Action collection ─────────────────────────────────────────────────────────

// collectActions gathers all explicitly named (non-wildcard) actions from the config.
func (e *Evaluator) collectActions() []string {
	seen := make(map[string]bool)

	add := func(a string) {
		al := strings.ToLower(a)
		if al == "*" || strings.HasSuffix(al, ":*") || strings.HasSuffix(al, "*") {
			return // skip wildcards — they can't be directly enumerated
		}
		if !seen[al] {
			seen[al] = true
		}
	}

	for _, r := range e.config.Roles {
		for _, a := range r.RolePolicyActions {
			add(a)
		}
		for _, a := range r.BoundaryActions {
			add(a)
		}
	}
	for _, bp := range e.config.BucketPolicies {
		for _, a := range bp.AllowActions {
			add(a)
		}
		for _, a := range bp.DenyActions {
			add(a)
		}
		if bp.Policy != nil {
			for _, stmt := range bp.Policy.Statements {
				for _, a := range stmt.Actions {
					add(a)
				}
			}
		}
	}
	for _, op := range e.config.OrgPolicies {
		for _, a := range op.AllowActions {
			add(a)
		}
		for _, a := range op.DenyActions {
			add(a)
		}
	}

	actions := make([]string, 0, len(seen))
	for a := range seen {
		actions = append(actions, a)
	}
	sort.Strings(actions)
	return actions
}

// roleName returns the display name for a role (AWS name if set, else TF name).
func roleName(r *ir.IAMRole) string {
	if r.Name != "" {
		return r.Name
	}
	return r.TFName
}
