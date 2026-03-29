// ============================================================
//  AUTO-GENERATED from: testdata
//  AWS policy evaluation
// ============================================================

// -- Type definitions -----------------------------------------
abstract sig TagValue {}
one sig TAG_DEV, TAG_PROD extends TagValue {}

abstract sig VpceId {}
one sig VPCE_0A1B2C3D extends VpceId {}
one sig VPCE_OTHER extends VpceId {}

abstract sig Action {}
one sig S3_All, S3_GetObject, S3_ListBucket, S3_Other extends Action {}

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
one sig bucket_secure_bucket extends S3Bucket {}
one sig bucket_data extends S3Bucket {}
one sig bucket_my_bucket extends S3Bucket {}
one sig policy_data extends BucketPolicy {}
one sig policy_deny_delete extends BucketPolicy {}
one sig role_developer extends IAMRole {}
one sig role_restricted_role extends IAMRole {}
one sig role_app_role extends IAMRole {}

fact ExactUniverse {
  S3Bucket     = bucket_secure_bucket + bucket_data + bucket_my_bucket
  BucketPolicy = policy_data + policy_deny_delete
  IAMRole      = role_developer + role_restricted_role + role_app_role
  Resource     = S3Bucket + BucketPolicy + IAMRole
}

// -- Configuration facts --------------------------------------
fact ConfigFacts {
  bucket_secure_bucket.envTag            = TAG_PROD
  bucket_secure_bucket.blockPublicAccess = False
  bucket_secure_bucket.dependsOn         = none

  bucket_data.envTag            = TAG_PROD
  bucket_data.blockPublicAccess = False
  bucket_data.dependsOn         = none

  bucket_my_bucket.envTag            = TAG_PROD
  bucket_my_bucket.blockPublicAccess = False
  bucket_my_bucket.dependsOn         = none

  policy_data.bucket         = bucket_data
  policy_data.denyAllExcept  = VPCE_0A1B2C3D
  policy_data.allowPrincipal = role_developer
  policy_data.allowActions   = S3_GetObject + S3_ListBucket
  policy_data.abacCondition  = True
  policy_data.dependsOn      = bucket_data

  policy_deny_delete.bucket         = bucket_my_bucket
  policy_deny_delete.denyAllExcept  = none
  policy_deny_delete.allowPrincipal = role_app_role
  policy_deny_delete.allowActions   = S3_GetObject + S3_ListBucket
  policy_deny_delete.abacCondition  = False
  policy_deny_delete.dependsOn      = bucket_my_bucket

  role_developer.envTag           = TAG_DEV
  role_developer.hasRolePolicy    = True
  role_developer.roleAllowActions = S3_GetObject + S3_ListBucket
  role_developer.dependsOn        = none

  role_restricted_role.envTag           = TAG_PROD
  role_restricted_role.hasRolePolicy    = True
  role_restricted_role.roleAllowActions = S3_All
  role_restricted_role.dependsOn        = none

  role_app_role.envTag           = TAG_PROD
  role_app_role.hasRolePolicy    = True
  role_app_role.roleAllowActions = S3_All
  role_app_role.dependsOn        = none


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

// Step 4: Resource Policy - bucket policy must allow principal + action + ABAC
pred resourcePolicyAllows[req: Request] {
  some bp: BucketPolicy |
    bp.bucket         = req.target    and
    bp.allowPrincipal = req.principal and
    req.action in bp.allowActions     and
    (bp.abacCondition = True implies
       req.principal.envTag = req.target.envTag)
}

// Step 5: Identity Policy - role must have policy allowing action
pred identityPolicyAllows[req: Request] {
  req.principal.hasRolePolicy = True and
  req.action in req.principal.roleAllowActions
}

// Final: all steps must pass for access
pred accessAllowed[req: Request] {
  not explicitDeny[req]     and
  resourcePolicyAllows[req] and
  identityPolicyAllows[req]
}


// ============================================================
//  ASSERTIONS - these fail when there's a misconfiguration
// ============================================================

// Main check: role should have access to bucket. Fails on ANY misconfiguration.
assert RoleHasAccess {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_GetObject and
     req.target = bucket_secure_bucket and
     req.sourceVpce = policy_data.denyAllExcept)
    implies accessAllowed[req]
}

// Step 1: Requests with wrong VPCE should be denied. Fails if denyAllExcept = none.
assert NoVpceBypass {
  all req: Request |
    (req.principal = role_developer and
     req.target = bucket_secure_bucket and
     req.sourceVpce = VPCE_OTHER)
    implies explicitDeny[req]
}

// Step 4: Role should pass resource policy. Fails on ABAC tag mismatch.
assert NoStep4Deny {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_GetObject and
     req.target = bucket_secure_bucket)
    implies resourcePolicyAllows[req]
}

// Step 5: Role should pass identity policy. Fails if hasRolePolicy = False.
assert NoStep5Deny {
  all req: Request |
    (req.principal = role_developer and
     req.action = S3_GetObject and
     req.target = bucket_secure_bucket)
    implies identityPolicyAllows[req]
}


// ============================================================
//  CHECKS
// ============================================================

check RoleHasAccess
  for exactly 3 S3Bucket, exactly 2 BucketPolicy, exactly 3 IAMRole,
      exactly 2 Request, exactly 2 VpceId, exactly 2 TagValue, exactly 3 Action, exactly 2 Bool

check NoVpceBypass
  for exactly 3 S3Bucket, exactly 2 BucketPolicy, exactly 3 IAMRole,
      exactly 2 Request, exactly 2 VpceId, exactly 2 TagValue, exactly 3 Action, exactly 2 Bool

check NoStep4Deny
  for exactly 3 S3Bucket, exactly 2 BucketPolicy, exactly 3 IAMRole,
      exactly 2 Request, exactly 2 VpceId, exactly 2 TagValue, exactly 3 Action, exactly 2 Bool

check NoStep5Deny
  for exactly 3 S3Bucket, exactly 2 BucketPolicy, exactly 3 IAMRole,
      exactly 2 Request, exactly 2 VpceId, exactly 2 TagValue, exactly 3 Action, exactly 2 Bool
