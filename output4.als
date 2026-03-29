// ============================================================
//  AUTO-GENERATED from: test.tf
//  AWS policy evaluation
// ============================================================

// -- Type definitions -----------------------------------------
abstract sig TagValue {}
one sig TAG_DEV, TAG_PROD extends TagValue {}

abstract sig VpceId {}
one sig VPCE_0A1B2C3D extends VpceId {}
one sig VPCE_OTHER extends VpceId {}

abstract sig Action {}
one sig S3_GetObject, S3_ListBucket, S3_Other extends Action {}

abstract sig Resource { dependsOn: set Resource }

sig S3Bucket extends Resource {
  envTag:            one TagValue,
  blockPublicAccess: one Bool
}

sig BucketPolicy extends Resource {
  bucket:         one S3Bucket,
  denyAllExcept:  lone VpceId,
  allowPrincipal: lone IAMRole,
  allowActions:   set Action,
  abacCondition:  one Bool
}

sig IAMRole extends Resource {
  envTag:           one TagValue,
  hasRolePolicy:    one Bool,
  roleAllowActions: set Action
}

abstract sig Bool {}
one sig True, False extends Bool {}

// -- Concrete resources ---------------------------------------
one sig bucket_data extends S3Bucket {}
one sig policy_data extends BucketPolicy {}
one sig role_developer extends IAMRole {}

fact ExactUniverse {
  S3Bucket     = bucket_data
  BucketPolicy = policy_data
  IAMRole      = role_developer
  Resource     = S3Bucket + BucketPolicy + IAMRole
}

// -- Configuration facts --------------------------------------
fact ConfigFacts {
  bucket_data.envTag            = TAG_PROD
  bucket_data.blockPublicAccess = False
  bucket_data.dependsOn         = none

  policy_data.bucket         = bucket_data
  policy_data.denyAllExcept  = VPCE_0A1B2C3D
  policy_data.allowPrincipal = role_developer
  policy_data.allowActions   = S3_GetObject + S3_ListBucket
  policy_data.abacCondition  = True
  policy_data.dependsOn      = bucket_data

  role_developer.envTag           = TAG_DEV
  role_developer.hasRolePolicy    = True
  role_developer.roleAllowActions = S3_GetObject + S3_ListBucket
  role_developer.dependsOn        = none


}

// ============================================================
//  PREDICATES
// ============================================================

sig Request {
  principal:  one IAMRole,
  action:     one Action,
  target:     one S3Bucket,
  sourceVpce: lone VpceId
}

// Step 1: Explicit Deny - VPCE guard blocks requests without correct VPCE
pred explicitDeny[req: Request] {
  some bp: BucketPolicy |
    bp.bucket        = req.target and
    bp.denyAllExcept != none      and
    req.sourceVpce  != bp.denyAllExcept
}

// Step 3: Resource Policy - bucket policy must allow principal + action + ABAC
pred resourcePolicyAllows[req: Request] {
  some bp: BucketPolicy |
    bp.bucket         = req.target    and
    bp.allowPrincipal = req.principal and
    req.action in bp.allowActions     and
    (bp.abacCondition = True implies
       req.principal.envTag = req.target.envTag)
}

// Step 6: Identity Policy - role must have policy allowing action
pred identityPolicyAllows[req: Request] {
  req.principal.hasRolePolicy = True and
  req.action in req.principal.roleAllowActions
}

// Final: no explicit deny, and either bucket policy OR identity policy grants access
pred accessAllowed[req: Request] {
  not explicitDeny[req] and
  (resourcePolicyAllows[req] or identityPolicyAllows[req])
}


// ============================================================
//  ASSERTIONS - these fail when there's a misconfiguration
// ============================================================

// Main check: role should have access to bucket via correct VPCE. Fails on ANY misconfiguration.
assert RoleHasAccess {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_GetObject and
     req.target = bucket_data and
     req.sourceVpce = policy_data.denyAllExcept)
    implies accessAllowed[req]
}

// Step 1: Requests with wrong VPCE should be denied. Fails if denyAllExcept = none.
assert NoVpceBypass {
  all req: Request |
    (req.principal = role_developer and
     req.target = bucket_data and
     req.sourceVpce = VPCE_OTHER)
    implies explicitDeny[req]
}

// Step 3: Role should pass resource policy. Fails on ABAC tag mismatch or missing allow.
assert NoStep3Deny {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_GetObject and
     req.target = bucket_data)
    implies resourcePolicyAllows[req]
}

// Step 6: Role should pass identity policy. Fails if hasRolePolicy = False or action not in policy.
assert NoStep6Deny {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_GetObject and
     req.target = bucket_data)
    implies identityPolicyAllows[req]
}


// ============================================================
//  CHECKS
// ============================================================

check RoleHasAccess
  for exactly 1 S3Bucket, exactly 1 BucketPolicy, exactly 1 IAMRole,
      exactly 2 Request, exactly 2 VpceId, exactly 2 TagValue, exactly 3 Action, exactly 2 Bool

check NoVpceBypass
  for exactly 1 S3Bucket, exactly 1 BucketPolicy, exactly 1 IAMRole,
      exactly 2 Request, exactly 2 VpceId, exactly 2 TagValue, exactly 3 Action, exactly 2 Bool

check NoStep3Deny
  for exactly 1 S3Bucket, exactly 1 BucketPolicy, exactly 1 IAMRole,
      exactly 2 Request, exactly 2 VpceId, exactly 2 TagValue, exactly 3 Action, exactly 2 Bool

check NoStep6Deny
  for exactly 1 S3Bucket, exactly 1 BucketPolicy, exactly 1 IAMRole,
      exactly 2 Request, exactly 2 VpceId, exactly 2 TagValue, exactly 3 Action, exactly 2 Bool
