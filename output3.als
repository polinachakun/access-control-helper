// ============================================================
//  AUTO-GENERATED from: scenario3.tf
//  AWS S3 Access Control — 7-layer policy evaluation model
// ============================================================

// ── Scalar domains ─────────────────────────────────────────────────────────
abstract sig TagValue {}
one sig TAG_DEV, TAG_PROD extends TagValue {}

abstract sig VpceId {}
one sig VPCE_OTHER extends VpceId {}

abstract sig Action {}
one sig S3_DeleteObject, S3_GetObject, S3_ListBucket, S3_PutObject extends Action {}

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
one sig bucket_secure_bucket extends S3Bucket {}
one sig role_restricted_role extends IAMRole {}

fact ExactUniverse {
  S3Bucket     = bucket_secure_bucket
  BucketPolicy = none
  OrgRCP       = none
  OrgSCP       = none
  IAMRole      = role_restricted_role
  Resource     = S3Bucket + BucketPolicy + OrgRCP + OrgSCP + IAMRole
}

// ── Configuration facts ─────────────────────────────────────────────────────
fact ConfigFacts {
  bucket_secure_bucket.envTag            = TAG_PROD
  bucket_secure_bucket.blockPublicAccess = False
  bucket_secure_bucket.dependsOn         = none

  role_restricted_role.envTag               = TAG_PROD
  role_restricted_role.hasRolePolicy        = True
  role_restricted_role.roleAllowActions     = S3_GetObject + S3_PutObject + S3_ListBucket + S3_DeleteObject
  role_restricted_role.hasBoundary          = True
  role_restricted_role.boundaryActions      = S3_GetObject
  role_restricted_role.hasSessionPolicy     = False
  role_restricted_role.sessionPolicyActions = none
  role_restricted_role.dependsOn            = none


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
//  PER-TRIPLE ACCESS ASSERTIONS — (principal, bucket, action)
// ============================================================

// Checks if restricted_role can perform S3_DeleteObject on secure_bucket.
assert RestrictedRoleCanDeleteObjectOnSecureBucket {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_DeleteObject and
     req.target = bucket_secure_bucket)
    implies accessAllowed[req]
}

// Layer 1: No explicit deny for restricted_role performing S3_DeleteObject on secure_bucket.
assert RestrictedRoleCanDeleteObjectOnSecureBucket_L1 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_DeleteObject and
     req.target = bucket_secure_bucket)
    implies not explicitDeny[req]
}

// Layer 2: RCP allows for restricted_role performing S3_DeleteObject on secure_bucket.
assert RestrictedRoleCanDeleteObjectOnSecureBucket_L2 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_DeleteObject and
     req.target = bucket_secure_bucket)
    implies rcpAllows[req]
}

// Layer 3: SCP allows for restricted_role performing S3_DeleteObject on secure_bucket.
assert RestrictedRoleCanDeleteObjectOnSecureBucket_L3 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_DeleteObject and
     req.target = bucket_secure_bucket)
    implies scpAllows[req]
}

// Layer 4: Resource policy allows or not applicable for restricted_role performing S3_DeleteObject on secure_bucket.
assert RestrictedRoleCanDeleteObjectOnSecureBucket_L4 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_DeleteObject and
     req.target = bucket_secure_bucket)
    implies resourcePolicyAllows[req] or resourcePolicyNotApplicable[req]
}

// Layer 5: Identity policy allows for restricted_role performing S3_DeleteObject on secure_bucket.
assert RestrictedRoleCanDeleteObjectOnSecureBucket_L5 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_DeleteObject and
     req.target = bucket_secure_bucket)
    implies identityPolicyAllows[req]
}

// Layer 6: Permission boundary allows for restricted_role performing S3_DeleteObject on secure_bucket.
assert RestrictedRoleCanDeleteObjectOnSecureBucket_L6 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_DeleteObject and
     req.target = bucket_secure_bucket)
    implies permBoundaryAllows[req]
}

// Layer 7: Session policy allows for restricted_role performing S3_DeleteObject on secure_bucket.
assert RestrictedRoleCanDeleteObjectOnSecureBucket_L7 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_DeleteObject and
     req.target = bucket_secure_bucket)
    implies sessionPolicyAllows[req]
}

// Checks if restricted_role can perform S3_GetObject on secure_bucket.
assert RestrictedRoleCanGetObjectOnSecureBucket {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_GetObject and
     req.target = bucket_secure_bucket)
    implies accessAllowed[req]
}

// Layer 1: No explicit deny for restricted_role performing S3_GetObject on secure_bucket.
assert RestrictedRoleCanGetObjectOnSecureBucket_L1 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_GetObject and
     req.target = bucket_secure_bucket)
    implies not explicitDeny[req]
}

// Layer 2: RCP allows for restricted_role performing S3_GetObject on secure_bucket.
assert RestrictedRoleCanGetObjectOnSecureBucket_L2 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_GetObject and
     req.target = bucket_secure_bucket)
    implies rcpAllows[req]
}

// Layer 3: SCP allows for restricted_role performing S3_GetObject on secure_bucket.
assert RestrictedRoleCanGetObjectOnSecureBucket_L3 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_GetObject and
     req.target = bucket_secure_bucket)
    implies scpAllows[req]
}

// Layer 4: Resource policy allows or not applicable for restricted_role performing S3_GetObject on secure_bucket.
assert RestrictedRoleCanGetObjectOnSecureBucket_L4 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_GetObject and
     req.target = bucket_secure_bucket)
    implies resourcePolicyAllows[req] or resourcePolicyNotApplicable[req]
}

// Layer 5: Identity policy allows for restricted_role performing S3_GetObject on secure_bucket.
assert RestrictedRoleCanGetObjectOnSecureBucket_L5 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_GetObject and
     req.target = bucket_secure_bucket)
    implies identityPolicyAllows[req]
}

// Layer 6: Permission boundary allows for restricted_role performing S3_GetObject on secure_bucket.
assert RestrictedRoleCanGetObjectOnSecureBucket_L6 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_GetObject and
     req.target = bucket_secure_bucket)
    implies permBoundaryAllows[req]
}

// Layer 7: Session policy allows for restricted_role performing S3_GetObject on secure_bucket.
assert RestrictedRoleCanGetObjectOnSecureBucket_L7 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_GetObject and
     req.target = bucket_secure_bucket)
    implies sessionPolicyAllows[req]
}

// Checks if restricted_role can perform S3_ListBucket on secure_bucket.
assert RestrictedRoleCanListBucketOnSecureBucket {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_ListBucket and
     req.target = bucket_secure_bucket)
    implies accessAllowed[req]
}

// Layer 1: No explicit deny for restricted_role performing S3_ListBucket on secure_bucket.
assert RestrictedRoleCanListBucketOnSecureBucket_L1 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_ListBucket and
     req.target = bucket_secure_bucket)
    implies not explicitDeny[req]
}

// Layer 2: RCP allows for restricted_role performing S3_ListBucket on secure_bucket.
assert RestrictedRoleCanListBucketOnSecureBucket_L2 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_ListBucket and
     req.target = bucket_secure_bucket)
    implies rcpAllows[req]
}

// Layer 3: SCP allows for restricted_role performing S3_ListBucket on secure_bucket.
assert RestrictedRoleCanListBucketOnSecureBucket_L3 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_ListBucket and
     req.target = bucket_secure_bucket)
    implies scpAllows[req]
}

// Layer 4: Resource policy allows or not applicable for restricted_role performing S3_ListBucket on secure_bucket.
assert RestrictedRoleCanListBucketOnSecureBucket_L4 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_ListBucket and
     req.target = bucket_secure_bucket)
    implies resourcePolicyAllows[req] or resourcePolicyNotApplicable[req]
}

// Layer 5: Identity policy allows for restricted_role performing S3_ListBucket on secure_bucket.
assert RestrictedRoleCanListBucketOnSecureBucket_L5 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_ListBucket and
     req.target = bucket_secure_bucket)
    implies identityPolicyAllows[req]
}

// Layer 6: Permission boundary allows for restricted_role performing S3_ListBucket on secure_bucket.
assert RestrictedRoleCanListBucketOnSecureBucket_L6 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_ListBucket and
     req.target = bucket_secure_bucket)
    implies permBoundaryAllows[req]
}

// Layer 7: Session policy allows for restricted_role performing S3_ListBucket on secure_bucket.
assert RestrictedRoleCanListBucketOnSecureBucket_L7 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_ListBucket and
     req.target = bucket_secure_bucket)
    implies sessionPolicyAllows[req]
}

// Checks if restricted_role can perform S3_PutObject on secure_bucket.
assert RestrictedRoleCanPutObjectOnSecureBucket {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_PutObject and
     req.target = bucket_secure_bucket)
    implies accessAllowed[req]
}

// Layer 1: No explicit deny for restricted_role performing S3_PutObject on secure_bucket.
assert RestrictedRoleCanPutObjectOnSecureBucket_L1 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_PutObject and
     req.target = bucket_secure_bucket)
    implies not explicitDeny[req]
}

// Layer 2: RCP allows for restricted_role performing S3_PutObject on secure_bucket.
assert RestrictedRoleCanPutObjectOnSecureBucket_L2 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_PutObject and
     req.target = bucket_secure_bucket)
    implies rcpAllows[req]
}

// Layer 3: SCP allows for restricted_role performing S3_PutObject on secure_bucket.
assert RestrictedRoleCanPutObjectOnSecureBucket_L3 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_PutObject and
     req.target = bucket_secure_bucket)
    implies scpAllows[req]
}

// Layer 4: Resource policy allows or not applicable for restricted_role performing S3_PutObject on secure_bucket.
assert RestrictedRoleCanPutObjectOnSecureBucket_L4 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_PutObject and
     req.target = bucket_secure_bucket)
    implies resourcePolicyAllows[req] or resourcePolicyNotApplicable[req]
}

// Layer 5: Identity policy allows for restricted_role performing S3_PutObject on secure_bucket.
assert RestrictedRoleCanPutObjectOnSecureBucket_L5 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_PutObject and
     req.target = bucket_secure_bucket)
    implies identityPolicyAllows[req]
}

// Layer 6: Permission boundary allows for restricted_role performing S3_PutObject on secure_bucket.
assert RestrictedRoleCanPutObjectOnSecureBucket_L6 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_PutObject and
     req.target = bucket_secure_bucket)
    implies permBoundaryAllows[req]
}

// Layer 7: Session policy allows for restricted_role performing S3_PutObject on secure_bucket.
assert RestrictedRoleCanPutObjectOnSecureBucket_L7 {
  all req: Request |
    (req.principal = role_restricted_role and
     req.action = S3_PutObject and
     req.target = bucket_secure_bucket)
    implies sessionPolicyAllows[req]
}


// ============================================================
//  CHECKS
// ============================================================

check RestrictedRoleCanDeleteObjectOnSecureBucket
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanDeleteObjectOnSecureBucket_L1
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanDeleteObjectOnSecureBucket_L2
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanDeleteObjectOnSecureBucket_L3
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanDeleteObjectOnSecureBucket_L4
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanDeleteObjectOnSecureBucket_L5
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanDeleteObjectOnSecureBucket_L6
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanDeleteObjectOnSecureBucket_L7
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanGetObjectOnSecureBucket
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanGetObjectOnSecureBucket_L1
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanGetObjectOnSecureBucket_L2
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanGetObjectOnSecureBucket_L3
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanGetObjectOnSecureBucket_L4
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanGetObjectOnSecureBucket_L5
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanGetObjectOnSecureBucket_L6
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanGetObjectOnSecureBucket_L7
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanListBucketOnSecureBucket
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanListBucketOnSecureBucket_L1
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanListBucketOnSecureBucket_L2
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanListBucketOnSecureBucket_L3
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanListBucketOnSecureBucket_L4
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanListBucketOnSecureBucket_L5
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanListBucketOnSecureBucket_L6
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanListBucketOnSecureBucket_L7
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanPutObjectOnSecureBucket
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanPutObjectOnSecureBucket_L1
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanPutObjectOnSecureBucket_L2
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanPutObjectOnSecureBucket_L3
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanPutObjectOnSecureBucket_L4
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanPutObjectOnSecureBucket_L5
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanPutObjectOnSecureBucket_L6
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool

check RestrictedRoleCanPutObjectOnSecureBucket_L7
  for exactly 1 S3Bucket, exactly 0 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 4 Request,
      exactly 1 VpceId, exactly 2 TagValue,
      exactly 4 Action, exactly 2 Bool
