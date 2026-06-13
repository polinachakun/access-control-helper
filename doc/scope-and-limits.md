# Scope and Limits

## Scope

The tool covers **same-account AWS S3 access control** derived from Terraform configurations.

**Principals:**
- IAM roles and users
- AWS service principals in bucket policies

**Policy evaluation layers:**
- Explicit deny (L1), RCP (L2), SCP (L3), resource-based (L4), identity-based (L5), permission boundary (L6)
- L4 and L5 are union within same account 

**Supported policy constructs:**
- `Action` and `NotAction` in Allow and Deny statements
- ABAC tag conditions (`aws:PrincipalTag/environment` with `StringEquals`)
- VPCE deny conditions (`aws:sourceVpce` with `StringNotEquals`)
- Multi-statement policies

**S3 resources and actions:**
- S3 buckets and bucket policies
- Block Public Access (`restrictPublicBuckets`, `blockPublicPolicy`)
- Bucket-level vs object-level resource matching
- Any explicit S3 action in the configuration, correctly classified by resource level

The tool is a formal prototype for a **selected subset** of AWS S3 access control and not a complete AWS policy simulator.

---

## Partial support

| Area | Status                                                                                                                                                                                                                                   |
|------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Cross-account access | Detection relies on explicit account IDs in assume-role ARN patterns; roles without a literal account ID (wildcards, service principals, missing ARN) are not detected as cross-account                                                  |
| Session policies | L7 is modeled and always passes,because session policies are runtime `sts:AssumeRole` parameters with no corresponding Terraform resource; static analysis cannot evaluate them                                                          |
| Public access block | `restrictPublicBuckets` and `blockPublicPolicy` block wildcard-principal grants; `blockPublicACLs` and `ignorePublicACLs` are not used (S3 ACLs are a deprecated legacy mechanism since April 2023) |

---

## Out of scope

**Principal types:**
- IAM groups and group policies
- Assumed-role sessions with session-specific context (MFA presence, source IP, token age)
- Web identity and SAML federation principals

**IAM policy language:**
- `NotResource`, `NotPrincipal`
- Policy variables (`${aws:username}`, `${aws:userid}`, etc.)
- Condition operators beyond `StringEquals` / `StringNotEquals`: numeric, date, IP address, ARN, `Bool`, `Null`, `ForAllValues`, `ForAnyValue`
- Condition keys beyond `aws:sourceVpce` and `aws:PrincipalTag/environment`

**S3 access surface:**
- Object Ownership and ACL semantics (deprecated legacy mechanism)
- Access Points, Multi-Region Access Points, S3 Object Lambda
- Pre-signed URLs (time-limited access signed by an IAM principal — no corresponding Terraform resource)
- VPC endpoint policies as a separate policy source
- KMS-related access interactions

**Account-level controls:**
- Block Public Access at account level (tool models bucket-level BPA only)
- IAM Identity Center (SSO) permission sets

**Terraform language:**
- Modules, variables, locals, `for_each`, `count`, dynamic blocks
- Conditionals and data-source-driven configurations
