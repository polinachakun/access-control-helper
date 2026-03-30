// ============================================================
//  AUTO-GENERATED from: scenario2.tf
//  AWS S3 Access Control — 7-layer policy evaluation model
// ============================================================

// ── Scalar domains ─────────────────────────────────────────────────────────
abstract sig TagValue {}
one sig TAG_DEV, TAG_PROD extends TagValue {}

abstract sig VpceId {}
one sig VPCE_OTHER extends VpceId {}

abstract sig Action {}
one sig S3_All, S3_DeleteObject, S3_GetObject, S3_ListBucket, S3_Other extends Action {}

abstract sig Bool {}
one sig True, False extends Bool {}

// ── Resource hierarchy ──────────────────────────────────────────────────────
abstract sig Resource { dependsOn: set Resource }

// S3 Bucket
sig S3Bucket extends Resource {
  envTag:            one TagValue,
  blockPublicAccess: one Bool
}

// Bucket Policy — resource-based policy evaluated at Layer 4
sig BucketPolicy extends Resource {
  bucket:         one S3Bucket,
  denyAllExcept:  lone VpceId,
  allowPrincipal: lone IAMRole,
  allowActions:   set Action,
  denyActions:    set Action,
  denyPrincipal:  lone IAMRole,
  abacCondition:  one Bool
}

// AWS Organizations Resource Control Policy (Layer 2)
abstract sig OrgRCP extends Resource {
  rcpAllowActions: set Action,
  rcpDenyActions:  set Action
}

// AWS Organizations Service Control Policy (Layer 3)
abstract sig OrgSCP extends Resource {
  scpAllowActions: set Action,
  scpDenyActions:  set Action
}

// IAM Role principal — identity policy (Layer 5), boundary (Layer 6), session (Layer 7)
sig IAMRole extends Resource {
  envTag:               one TagValue,
  hasRolePolicy:        one Bool,
  roleAllowActions:     set Action,
  hasBoundary:          one Bool,
  boundaryActions:      set Action,
  hasSessionPolicy:     one Bool,
  sessionPolicyActions: set Action
}

// ── Concrete resources ──────────────────────────────────────────────────────
one sig bucket_my_bucket extends S3Bucket {}
one sig policy_deny_delete extends BucketPolicy {}
one sig role_app_role extends IAMRole {}

fact ExactUniverse {
  S3Bucket     = bucket_my_bucket
  BucketPolicy = policy_deny_delete
  OrgRCP       = none
  OrgSCP       = none
  IAMRole      = role_app_role
  Resource     = S3Bucket + BucketPolicy + OrgRCP + OrgSCP + IAMRole
}

// ── Configuration facts ─────────────────────────────────────────────────────
fact ConfigFacts {
  bucket_my_bucket.envTag            = TAG_PROD
  bucket_my_bucket.blockPublicAccess = False
  bucket_my_bucket.dependsOn         = none

  policy_deny_delete.bucket         = bucket_my_bucket
  policy_deny_delete.denyAllExcept  = none
  policy_deny_delete.allowPrincipal = role_app_role
  policy_deny_delete.allowActions   = S3_GetObject + S3_ListBucket
  policy_deny_delete.denyActions    = S3_DeleteObject
  policy_deny_delete.denyPrincipal  = none
  policy_deny_delete.abacCondition  = False
  policy_deny_delete.dependsOn      = bucket_my_bucket

  role_app_role.envTag               = TAG_PROD
  role_app_role.hasRolePolicy        = True
  role_app_role.roleAllowActions     = Action
  role_app_role.hasBoundary          = False
  role_app_role.boundaryActions      = none
  role_app_role.hasSessionPolicy     = False
  role_app_role.sessionPolicyActions = none
  role_app_role.dependsOn            = none


}

// ============================================================
//  REQUEST SIGNATURE
// ============================================================

sig Request {
  principal:  one IAMRole,
  action:     one Action,
  target:     one S3Bucket,
  sourceVpce: lone VpceId
}

// ============================================================
//  EVALUATION PREDICATES — AWS 7-layer policy evaluation order
// ============================================================

// Layer 1a: VPCE guard — bucket policy denies requests without the required VPCE.
pred explicitDenyVpce[req: Request] {
  some bp: BucketPolicy |
    bp.bucket        = req.target and
    bp.denyAllExcept != none      and
    req.sourceVpce  != bp.denyAllExcept
}

// Layer 1b: Explicit Deny statement in bucket policy matching action and (optionally) principal.
pred explicitDenyAction[req: Request] {
  some bp: BucketPolicy |
    bp.bucket = req.target and
    req.action in bp.denyActions and
    (bp.denyPrincipal = none or bp.denyPrincipal = req.principal)
}

// Layer 1: Any explicit deny fires — VPCE guard OR explicit Deny statement wins immediately.
pred explicitDeny[req: Request] {
  explicitDenyVpce[req] or explicitDenyAction[req]
}

// Layer 2: AWS Organizations RCPs — action must be allowed by every RCP; no RCP means pass-through.
pred rcpAllows[req: Request] {
  no OrgRCP or
  (all rcp: OrgRCP |
    req.action in rcp.rcpAllowActions and
    req.action not in rcp.rcpDenyActions)
}

// Layer 3: AWS Organizations SCPs — action must be allowed by every SCP; no SCP means pass-through.
pred scpAllows[req: Request] {
  no OrgSCP or
  (all scp: OrgSCP |
    req.action in scp.scpAllowActions and
    req.action not in scp.scpDenyActions)
}

// Layer 4: Resource-based policy — bucket policy allows principal + action (+ ABAC tag match when required).
pred resourcePolicyAllows[req: Request] {
  some bp: BucketPolicy |
    bp.bucket         = req.target    and
    bp.allowPrincipal = req.principal and
    req.action in bp.allowActions     and
    (bp.abacCondition = True implies
       req.principal.envTag = req.target.envTag)
}

// Layer 5: Identity-based policy — the IAM role has a policy that explicitly allows the action.
pred identityPolicyAllows[req: Request] {
  req.principal.hasRolePolicy = True and
  req.action in req.principal.roleAllowActions
}

// Layer 6: IAM Permission Boundary — if a boundary is set, the action must appear in its allow set.
pred permBoundaryAllows[req: Request] {
  req.principal.hasBoundary = False or
  req.action in req.principal.boundaryActions
}

// Layer 7: Session Policy — if a session policy is present, the action must appear in its allow set.
pred sessionPolicyAllows[req: Request] {
  req.principal.hasSessionPolicy = False or
  req.action in req.principal.sessionPolicyActions
}

// Final: all 7 layers must pass — no explicit deny and at least one grant path (resource OR identity policy).
pred accessAllowed[req: Request] {
  not explicitDeny[req] and
  rcpAllows[req] and
  scpAllows[req] and
  (resourcePolicyAllows[req] or identityPolicyAllows[req]) and
  permBoundaryAllows[req] and
  sessionPolicyAllows[req]
}


// ============================================================
//  SCENARIO ASSERTIONS
// ============================================================

// Main: role must reach the bucket with the correct VPCE (all 7 layers pass).
assert RoleHasAccess {
  all req: Request |
    (req.principal = role_app_role and
     req.action = S3_GetObject and
     req.target = bucket_my_bucket and
     req.sourceVpce = policy_deny_delete.denyAllExcept)
    implies accessAllowed[req]
}

// Layer 1: Requests with the wrong VPCE must be denied — verifies the VPCE guard is active.
assert NoVpceBypass {
  all req: Request |
    (req.principal = role_app_role and
     req.target = bucket_my_bucket and
     req.sourceVpce = VPCE_OTHER)
    implies explicitDeny[req]
}

// Layer 4: Bucket policy must allow the principal + S3:GetObject.
assert NoLayer4Deny {
  all req: Request | (req.principal = role_app_role and
     req.action = S3_GetObject and
     req.target = bucket_my_bucket) implies resourcePolicyAllows[req]
}

// Layer 2: RCP must allow S3:GetObject (passes trivially when no RCPs are configured).
assert NoLayer2Deny {
  all req: Request | (req.principal = role_app_role and
     req.action = S3_GetObject and
     req.target = bucket_my_bucket) implies rcpAllows[req]
}

// Layer 3: SCP must allow S3:GetObject (passes trivially when no SCPs are configured).
assert NoLayer3Deny {
  all req: Request | (req.principal = role_app_role and
     req.action = S3_GetObject and
     req.target = bucket_my_bucket) implies scpAllows[req]
}

// Layer 5: Identity policy must allow S3:GetObject.
assert NoLayer5Deny {
  all req: Request | (req.principal = role_app_role and
     req.action = S3_GetObject and
     req.target = bucket_my_bucket) implies identityPolicyAllows[req]
}

// Layer 6: Permission boundary must allow S3:GetObject (passes trivially when no boundary is set).
assert NoLayer6Deny {
  all req: Request | (req.principal = role_app_role and
     req.action = S3_GetObject and
     req.target = bucket_my_bucket) implies permBoundaryAllows[req]
}

// Layer 7: Session policy must allow S3:GetObject (passes trivially when no session policy is set).
assert NoLayer7Deny {
  all req: Request | (req.principal = role_app_role and
     req.action = S3_GetObject and
     req.target = bucket_my_bucket) implies sessionPolicyAllows[req]
}


// ============================================================
//  PER-TRIPLE ACCESS ASSERTIONS — (principal, bucket, action)
// ============================================================

// Checks if app_role can perform S3_All on my_bucket.
assert AppRoleCanAllOnMyBucket {
  all req: Request |
    (req.principal = role_app_role and
     req.action = S3_All and
     req.target = bucket_my_bucket)
    implies accessAllowed[req]
}

// Checks if app_role can perform S3_DeleteObject on my_bucket.
assert AppRoleCanDeleteObjectOnMyBucket {
  all req: Request |
    (req.principal = role_app_role and
     req.action = S3_DeleteObject and
     req.target = bucket_my_bucket)
    implies accessAllowed[req]
}

// Checks if app_role can perform S3_GetObject on my_bucket.
assert AppRoleCanGetObjectOnMyBucket {
  all req: Request |
    (req.principal = role_app_role and
     req.action = S3_GetObject and
     req.target = bucket_my_bucket)
    implies accessAllowed[req]
}

// Checks if app_role can perform S3_ListBucket on my_bucket.
assert AppRoleCanListBucketOnMyBucket {
  all req: Request |
    (req.principal = role_app_role and
     req.action = S3_ListBucket and
     req.target = bucket_my_bucket)
    implies accessAllowed[req]
}

// Checks if app_role can perform S3_Other on my_bucket.
assert AppRoleCanOtherOnMyBucket {
  all req: Request |
    (req.principal = role_app_role and
     req.action = S3_Other and
     req.target = bucket_my_bucket)
    implies accessAllowed[req]
}


// ============================================================
//  CHECKS
// ============================================================

check RoleHasAccess
  for exactly 1 S3Bucket, exactly 1 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 5 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 5 Action, exactly 2 Bool

check NoVpceBypass
  for exactly 1 S3Bucket, exactly 1 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 5 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 5 Action, exactly 2 Bool

check NoLayer4Deny
  for exactly 1 S3Bucket, exactly 1 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 5 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 5 Action, exactly 2 Bool

check NoLayer2Deny
  for exactly 1 S3Bucket, exactly 1 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 5 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 5 Action, exactly 2 Bool

check NoLayer3Deny
  for exactly 1 S3Bucket, exactly 1 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 5 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 5 Action, exactly 2 Bool

check NoLayer5Deny
  for exactly 1 S3Bucket, exactly 1 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 5 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 5 Action, exactly 2 Bool

check NoLayer6Deny
  for exactly 1 S3Bucket, exactly 1 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 5 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 5 Action, exactly 2 Bool

check NoLayer7Deny
  for exactly 1 S3Bucket, exactly 1 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 5 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 5 Action, exactly 2 Bool

check AppRoleCanAllOnMyBucket
  for exactly 1 S3Bucket, exactly 1 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 5 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 5 Action, exactly 2 Bool

check AppRoleCanDeleteObjectOnMyBucket
  for exactly 1 S3Bucket, exactly 1 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 5 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 5 Action, exactly 2 Bool

check AppRoleCanGetObjectOnMyBucket
  for exactly 1 S3Bucket, exactly 1 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 5 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 5 Action, exactly 2 Bool

check AppRoleCanListBucketOnMyBucket
  for exactly 1 S3Bucket, exactly 1 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 5 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 5 Action, exactly 2 Bool

check AppRoleCanOtherOnMyBucket
  for exactly 1 S3Bucket, exactly 1 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 5 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 5 Action, exactly 2 Bool
