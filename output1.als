// ============================================================
//  AUTO-GENERATED from: scenario1.tf
//  AWS S3 Access Control — 7-layer policy evaluation model
// ============================================================

// ── Scalar domains ─────────────────────────────────────────────────────────
abstract sig TagValue {}
one sig TAG_DEV, TAG_PROD extends TagValue {}

abstract sig VpceId {}
one sig VPCE_OTHER extends VpceId {}

abstract sig Action {}
one sig S3_GetObject extends Action {}

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
  bucket:            one S3Bucket,
  denyAllExcept:     lone VpceId,
  allowPrincipal:    lone IAMRole,
  allowAnyPrincipal: one Bool,
  allowActions:      set Action,
  denyActions:       set Action,
  denyPrincipal:     lone IAMRole,
  denyAnyPrincipal:  one Bool,
  abacCondition:     one Bool
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
one sig role_app_role extends IAMRole {}

fact ExactUniverse {
  S3Bucket     = bucket_my_bucket
  BucketPolicy = none
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

  role_app_role.envTag               = TAG_PROD
  role_app_role.hasRolePolicy        = True
  role_app_role.roleAllowActions     = S3_GetObject
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

// Layer 1b: Explicit Deny statement in bucket policy matching action and principal.
pred explicitDenyAction[req: Request] {
  some bp: BucketPolicy |
    bp.bucket = req.target and
    req.action in bp.denyActions and
    (bp.denyAnyPrincipal = True or bp.denyPrincipal = req.principal)
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
    bp.bucket = req.target and
    req.action in bp.allowActions and
    (bp.allowAnyPrincipal = True or bp.allowPrincipal = req.principal) and
    (bp.abacCondition = True implies
       req.principal.envTag = req.target.envTag)
}

// Layer 4: No resource-based policy applies to this request's target bucket.
pred resourcePolicyNotApplicable[req: Request] {
  no bp: BucketPolicy | bp.bucket = req.target
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

// Final: no explicit deny, all limiting layers pass, and at least one grant path allows.
pred accessAllowed[req: Request] {
  not explicitDeny[req] and
  rcpAllows[req] and
  scpAllows[req] and
  grantPathAllows[req] and
  permBoundaryAllows[req] and
  sessionPolicyAllows[req]
}

// Grant path: at least one of resource policy or identity policy allows the request.
pred grantPathAllows[req: Request] {
  resourcePolicyAllows[req] or identityPolicyAllows[req]
}


// ============================================================
//  PER-TRIPLE ACCESS ASSERTIONS — (principal, bucket, action)
// ============================================================

// Checks if app_role can perform S3_GetObject on my_bucket.
assert AppRoleCanGetObjectOnMyBucket {
  all req: Request |
    (req.principal = role_app_role and
     req.action = S3_GetObject and
     req.target = bucket_my_bucket)
    implies accessAllowed[req]
}

// Layer 1: No explicit deny for app_role performing S3_GetObject on my_bucket.
assert AppRoleCanGetObjectOnMyBucket_L1 {
  all req: Request |
    (req.principal = role_app_role and
     req.action = S3_GetObject and
     req.target = bucket_my_bucket)
    implies not explicitDeny[req]
}

// Layer 2: RCP allows for app_role performing S3_GetObject on my_bucket.
assert AppRoleCanGetObjectOnMyBucket_L2 {
  all req: Request |
    (req.principal = role_app_role and
     req.action = S3_GetObject and
     req.target = bucket_my_bucket)
    implies rcpAllows[req]
}

// Layer 3: SCP allows for app_role performing S3_GetObject on my_bucket.
assert AppRoleCanGetObjectOnMyBucket_L3 {
  all req: Request |
    (req.principal = role_app_role and
     req.action = S3_GetObject and
     req.target = bucket_my_bucket)
    implies scpAllows[req]
}

// Layer 4: Resource policy allows or not applicable for app_role performing S3_GetObject on my_bucket.
assert AppRoleCanGetObjectOnMyBucket_L4 {
  all req: Request |
    (req.principal = role_app_role and
     req.action = S3_GetObject and
     req.target = bucket_my_bucket)
    implies resourcePolicyAllows[req] or resourcePolicyNotApplicable[req]
}

// Layer 5: Identity policy allows for app_role performing S3_GetObject on my_bucket.
assert AppRoleCanGetObjectOnMyBucket_L5 {
  all req: Request |
    (req.principal = role_app_role and
     req.action = S3_GetObject and
     req.target = bucket_my_bucket)
    implies identityPolicyAllows[req]
}

// Layer 6: Permission boundary allows for app_role performing S3_GetObject on my_bucket.
assert AppRoleCanGetObjectOnMyBucket_L6 {
  all req: Request |
    (req.principal = role_app_role and
     req.action = S3_GetObject and
     req.target = bucket_my_bucket)
    implies permBoundaryAllows[req]
}

// Layer 7: Session policy allows for app_role performing S3_GetObject on my_bucket.
assert AppRoleCanGetObjectOnMyBucket_L7 {
  all req: Request |
    (req.principal = role_app_role and
     req.action = S3_GetObject and
     req.target = bucket_my_bucket)
    implies sessionPolicyAllows[req]
}


// ============================================================
//  CHECKS
// ============================================================

check AppRoleCanGetObjectOnMyBucket
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 1 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 1 Action, exactly 2 Bool

check AppRoleCanGetObjectOnMyBucket_L1
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 1 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 1 Action, exactly 2 Bool

check AppRoleCanGetObjectOnMyBucket_L2
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 1 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 1 Action, exactly 2 Bool

check AppRoleCanGetObjectOnMyBucket_L3
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 1 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 1 Action, exactly 2 Bool

check AppRoleCanGetObjectOnMyBucket_L4
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 1 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 1 Action, exactly 2 Bool

check AppRoleCanGetObjectOnMyBucket_L5
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 1 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 1 Action, exactly 2 Bool

check AppRoleCanGetObjectOnMyBucket_L6
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 1 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 1 Action, exactly 2 Bool

check AppRoleCanGetObjectOnMyBucket_L7
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 1 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 1 Action, exactly 2 Bool
