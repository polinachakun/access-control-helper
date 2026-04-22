// ============================================================
//  AUTO-GENERATED from: test.tf
//  AWS S3 Access Control — 7-layer policy evaluation model
// ============================================================

// ── Scalar domains ─────────────────────────────────────────────────────────
abstract sig TagValue {}
one sig TAG_DEV, TAG_PROD extends TagValue {}

abstract sig VpceId {}
one sig VPCE_0A1B2C3D extends VpceId {}
one sig VPCE_OTHER extends VpceId {}

abstract sig Action {}
one sig S3_GetObject, S3_ListBucket extends Action {}

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
  bucket:              one S3Bucket,
  denyAllExcept:       lone VpceId,

  allowPrincipal:      lone IAMRole,
  allowAnyPrincipal:   one Bool,
  allowActions:        set Action,
  allowBucketResource: one Bool,
  allowObjectResource: one Bool,

  denyActions:         set Action,
  denyPrincipal:       lone IAMRole,
  denyAnyPrincipal:    one Bool,
  denyBucketResource:  one Bool,
  denyObjectResource:  one Bool,

  abacCondition:       one Bool
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
one sig bucket_data extends S3Bucket {}
one sig policy_data_stmt_1_pr_1 extends BucketPolicy {}
one sig policy_data_stmt_2_pr_1 extends BucketPolicy {}
one sig role_developer extends IAMRole {}

fact ExactUniverse {
  S3Bucket     = bucket_data
  BucketPolicy = policy_data_stmt_1_pr_1 + policy_data_stmt_2_pr_1
  OrgRCP       = none
  OrgSCP       = none
  IAMRole      = role_developer
  Resource     = S3Bucket + BucketPolicy + OrgRCP + OrgSCP + IAMRole
}

// ── Configuration facts ─────────────────────────────────────────────────────
fact ConfigFacts {
  bucket_data.envTag            = TAG_PROD
  bucket_data.blockPublicAccess = False
  bucket_data.dependsOn         = none

  policy_data_stmt_1_pr_1.bucket              = bucket_data
  policy_data_stmt_1_pr_1.denyAllExcept       = VPCE_0A1B2C3D
  policy_data_stmt_1_pr_1.allowPrincipal      = none
  policy_data_stmt_1_pr_1.allowAnyPrincipal   = False
  policy_data_stmt_1_pr_1.allowActions        = none
  policy_data_stmt_1_pr_1.allowBucketResource = True
  policy_data_stmt_1_pr_1.allowObjectResource = True
  policy_data_stmt_1_pr_1.denyActions         = none
  policy_data_stmt_1_pr_1.denyPrincipal       = none
  policy_data_stmt_1_pr_1.denyAnyPrincipal    = False
  policy_data_stmt_1_pr_1.denyBucketResource  = True
  policy_data_stmt_1_pr_1.denyObjectResource  = True
  policy_data_stmt_1_pr_1.abacCondition       = False
  policy_data_stmt_1_pr_1.dependsOn           = bucket_data

  policy_data_stmt_2_pr_1.bucket              = bucket_data
  policy_data_stmt_2_pr_1.denyAllExcept       = none
  policy_data_stmt_2_pr_1.allowPrincipal      = role_developer
  policy_data_stmt_2_pr_1.allowAnyPrincipal   = False
  policy_data_stmt_2_pr_1.allowActions        = S3_GetObject + S3_ListBucket
  policy_data_stmt_2_pr_1.allowBucketResource = True
  policy_data_stmt_2_pr_1.allowObjectResource = True
  policy_data_stmt_2_pr_1.denyActions         = none
  policy_data_stmt_2_pr_1.denyPrincipal       = none
  policy_data_stmt_2_pr_1.denyAnyPrincipal    = False
  policy_data_stmt_2_pr_1.denyBucketResource  = True
  policy_data_stmt_2_pr_1.denyObjectResource  = True
  policy_data_stmt_2_pr_1.abacCondition       = True
  policy_data_stmt_2_pr_1.dependsOn           = bucket_data

  role_developer.envTag               = TAG_DEV
  role_developer.hasRolePolicy        = False
  role_developer.roleAllowActions     = none
  role_developer.hasBoundary          = False
  role_developer.boundaryActions      = none
  role_developer.hasSessionPolicy     = False
  role_developer.sessionPolicyActions = none
  role_developer.dependsOn            = none


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

// Layer 1a: VPCE guard — deny applies only if statement resource scope matches the action.
pred explicitDenyVpce[req: Request] {
  some bp: BucketPolicy |
    bp.bucket = req.target and
    bp.denyAllExcept != none and
    statementMatchesResource[req, bp.denyBucketResource, bp.denyObjectResource] and
    req.sourceVpce != bp.denyAllExcept
}

// Layer 1b: Explicit Deny statement in bucket policy matching action, principal, and resource scope.
pred explicitDenyAction[req: Request] {
  some bp: BucketPolicy |
    bp.bucket = req.target and
    req.action in bp.denyActions and
    statementMatchesResource[req, bp.denyBucketResource, bp.denyObjectResource] and
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

// Layer 4: Resource-based policy — statement must match principal, action, resource scope, and ABAC condition.
pred resourcePolicyAllows[req: Request] {
  some bp: BucketPolicy |
    bp.bucket = req.target and
    req.action in bp.allowActions and
    statementMatchesResource[req, bp.allowBucketResource, bp.allowObjectResource] and
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

// Final: no explicit deny, limiting layers pass, and at least one grant path allows.
pred accessAllowed[req: Request] {
  not explicitDeny[req] and
  rcpAllows[req] and
  scpAllows[req] and
  grantPathAllows[req] and
  permBoundaryAllows[req] and
  sessionPolicyAllows[req]
}

// At least one same-account grant path allows the request.
pred grantPathAllows[req: Request] {
  resourcePolicyAllows[req] or identityPolicyAllows[req]
}

// True for bucket-level S3 actions.
pred actionTargetsBucket[a: Action] {
  a = S3_ListBucket
}

// True for object-level S3 actions.
pred actionTargetsObject[a: Action] {
  a = S3_GetObject
}

// A policy statement applies only when its resource scope matches the action's required S3 resource type.
pred statementMatchesResource[req: Request, bucketRes: Bool, objectRes: Bool] {
  (actionTargetsBucket[req.action] and bucketRes = True) or
  (actionTargetsObject[req.action] and objectRes = True)
}


// ============================================================
//  PER-TRIPLE ACCESS ASSERTIONS — (principal, bucket, action)
// ============================================================

// Checks if developer can perform S3_GetObject on data.
assert DeveloperCanGetObjectOnData {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_GetObject and
     req.target = bucket_data)
    implies accessAllowed[req]
}

// Layer 1: No explicit deny for developer performing S3_GetObject on data.
assert DeveloperCanGetObjectOnData_L1 {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_GetObject and
     req.target = bucket_data)
    implies not explicitDeny[req]
}

// Layer 2: RCP allows for developer performing S3_GetObject on data.
assert DeveloperCanGetObjectOnData_L2 {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_GetObject and
     req.target = bucket_data)
    implies rcpAllows[req]
}

// Layer 3: SCP allows for developer performing S3_GetObject on data.
assert DeveloperCanGetObjectOnData_L3 {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_GetObject and
     req.target = bucket_data)
    implies scpAllows[req]
}

// Layer 4: Resource policy allows or not applicable for developer performing S3_GetObject on data.
assert DeveloperCanGetObjectOnData_L4 {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_GetObject and
     req.target = bucket_data)
    implies resourcePolicyAllows[req] or resourcePolicyNotApplicable[req]
}

// Layer 5: Identity policy allows for developer performing S3_GetObject on data.
assert DeveloperCanGetObjectOnData_L5 {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_GetObject and
     req.target = bucket_data)
    implies identityPolicyAllows[req]
}

// Layer 6: Permission boundary allows for developer performing S3_GetObject on data.
assert DeveloperCanGetObjectOnData_L6 {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_GetObject and
     req.target = bucket_data)
    implies permBoundaryAllows[req]
}

// Layer 7: Session policy allows for developer performing S3_GetObject on data.
assert DeveloperCanGetObjectOnData_L7 {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_GetObject and
     req.target = bucket_data)
    implies sessionPolicyAllows[req]
}

// Checks if developer can perform S3_ListBucket on data.
assert DeveloperCanListBucketOnData {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_ListBucket and
     req.target = bucket_data)
    implies accessAllowed[req]
}

// Layer 1: No explicit deny for developer performing S3_ListBucket on data.
assert DeveloperCanListBucketOnData_L1 {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_ListBucket and
     req.target = bucket_data)
    implies not explicitDeny[req]
}

// Layer 2: RCP allows for developer performing S3_ListBucket on data.
assert DeveloperCanListBucketOnData_L2 {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_ListBucket and
     req.target = bucket_data)
    implies rcpAllows[req]
}

// Layer 3: SCP allows for developer performing S3_ListBucket on data.
assert DeveloperCanListBucketOnData_L3 {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_ListBucket and
     req.target = bucket_data)
    implies scpAllows[req]
}

// Layer 4: Resource policy allows or not applicable for developer performing S3_ListBucket on data.
assert DeveloperCanListBucketOnData_L4 {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_ListBucket and
     req.target = bucket_data)
    implies resourcePolicyAllows[req] or resourcePolicyNotApplicable[req]
}

// Layer 5: Identity policy allows for developer performing S3_ListBucket on data.
assert DeveloperCanListBucketOnData_L5 {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_ListBucket and
     req.target = bucket_data)
    implies identityPolicyAllows[req]
}

// Layer 6: Permission boundary allows for developer performing S3_ListBucket on data.
assert DeveloperCanListBucketOnData_L6 {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_ListBucket and
     req.target = bucket_data)
    implies permBoundaryAllows[req]
}

// Layer 7: Session policy allows for developer performing S3_ListBucket on data.
assert DeveloperCanListBucketOnData_L7 {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_ListBucket and
     req.target = bucket_data)
    implies sessionPolicyAllows[req]
}


// ============================================================
//  CHECKS
// ============================================================

check DeveloperCanGetObjectOnData
  for exactly 1 S3Bucket, exactly 2 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 2 Request,
      exactly 2 VpceId, exactly 2 TagValue,
      exactly 2 Action, exactly 2 Bool

check DeveloperCanGetObjectOnData_L1
  for exactly 1 S3Bucket, exactly 2 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 2 Request,
      exactly 2 VpceId, exactly 2 TagValue,
      exactly 2 Action, exactly 2 Bool

check DeveloperCanGetObjectOnData_L2
  for exactly 1 S3Bucket, exactly 2 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 2 Request,
      exactly 2 VpceId, exactly 2 TagValue,
      exactly 2 Action, exactly 2 Bool

check DeveloperCanGetObjectOnData_L3
  for exactly 1 S3Bucket, exactly 2 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 2 Request,
      exactly 2 VpceId, exactly 2 TagValue,
      exactly 2 Action, exactly 2 Bool

check DeveloperCanGetObjectOnData_L4
  for exactly 1 S3Bucket, exactly 2 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 2 Request,
      exactly 2 VpceId, exactly 2 TagValue,
      exactly 2 Action, exactly 2 Bool

check DeveloperCanGetObjectOnData_L5
  for exactly 1 S3Bucket, exactly 2 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 2 Request,
      exactly 2 VpceId, exactly 2 TagValue,
      exactly 2 Action, exactly 2 Bool

check DeveloperCanGetObjectOnData_L6
  for exactly 1 S3Bucket, exactly 2 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 2 Request,
      exactly 2 VpceId, exactly 2 TagValue,
      exactly 2 Action, exactly 2 Bool

check DeveloperCanGetObjectOnData_L7
  for exactly 1 S3Bucket, exactly 2 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 2 Request,
      exactly 2 VpceId, exactly 2 TagValue,
      exactly 2 Action, exactly 2 Bool

check DeveloperCanListBucketOnData
  for exactly 1 S3Bucket, exactly 2 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 2 Request,
      exactly 2 VpceId, exactly 2 TagValue,
      exactly 2 Action, exactly 2 Bool

check DeveloperCanListBucketOnData_L1
  for exactly 1 S3Bucket, exactly 2 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 2 Request,
      exactly 2 VpceId, exactly 2 TagValue,
      exactly 2 Action, exactly 2 Bool

check DeveloperCanListBucketOnData_L2
  for exactly 1 S3Bucket, exactly 2 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 2 Request,
      exactly 2 VpceId, exactly 2 TagValue,
      exactly 2 Action, exactly 2 Bool

check DeveloperCanListBucketOnData_L3
  for exactly 1 S3Bucket, exactly 2 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 2 Request,
      exactly 2 VpceId, exactly 2 TagValue,
      exactly 2 Action, exactly 2 Bool

check DeveloperCanListBucketOnData_L4
  for exactly 1 S3Bucket, exactly 2 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 2 Request,
      exactly 2 VpceId, exactly 2 TagValue,
      exactly 2 Action, exactly 2 Bool

check DeveloperCanListBucketOnData_L5
  for exactly 1 S3Bucket, exactly 2 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 2 Request,
      exactly 2 VpceId, exactly 2 TagValue,
      exactly 2 Action, exactly 2 Bool

check DeveloperCanListBucketOnData_L6
  for exactly 1 S3Bucket, exactly 2 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 2 Request,
      exactly 2 VpceId, exactly 2 TagValue,
      exactly 2 Action, exactly 2 Bool

check DeveloperCanListBucketOnData_L7
  for exactly 1 S3Bucket, exactly 2 BucketPolicy,
      exactly 0 OrgRCP, exactly 0 OrgSCP,
      exactly 1 IAMRole, exactly 2 Request,
      exactly 2 VpceId, exactly 2 TagValue,
      exactly 2 Action, exactly 2 Bool
