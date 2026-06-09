# Manual Verification Scenarios

Real AWS infrastructure used to manually validate that the tool's access-control
analysis matches actual IAM behaviour. Each scenario deploys a minimal set of
resources, then provides copy-paste CLI commands to confirm every allow/deny
decision with `aws iam simulate-principal-policy`.

---

## Prerequisites

- Terraform ≥ 1.5
- AWS credentials with IAM + S3 (+ Organizations for SCP/RCP scenarios) access
- `aws` CLI configured for the target account

---

## Quick start

```bash
# Deploy scenario and print validation commands
./validate_all.sh 01

# With a custom suffix to avoid name conflicts
./validate_all.sh 04 mytest123

# SCP/RCP scenarios require an OU or account target ID
./validate_all.sh 04 mytest123 ou-ab12-xxxxxxxx

# Clean up after validation
cd 01_identity_allow_only && terraform destroy -var=suffix=<same-suffix>
```

---

## Scenarios

| # | Folder | What it tests |
|---|--------|--------------|
| 01 | `01_identity_allow_only` | Identity policy alone is sufficient to grant access  |
| 02 | `02_explicit_deny_wins` | Explicit Deny in bucket policy overrides a broad identity Allow |
| 03 | `03_permission_boundary_blocks` | Permission boundary narrows effective permissions below what identity policy grants |
| 04 | `04_scp_blocks_allow` | SCP at org level blocks an action even when identity policy allows it |
| 05 | `05_rcp_blocks_allow` | RCP on the resource side blocks an action even when identity policy allows it |
| 06 | `06_scp_restricts_account_wide` | SCP applies account-wide — restricts all roles including admin |
| 07 | `07_service_principal_allow` | Bucket policy grants access to a service principal (`lambda.amazonaws.com`) |
| 08 | `08_vpce_and_abac_deny` | Bucket policy denies access unless request comes via VPC endpoint and matches tag condition |
| 09 | `09_scp_and_boundary_combined` | SCP and permission boundary restrict independently — both must pass |
| 10 | `10_notaction_identity` | `NotAction` in identity policy implicitly denies the excluded action |

