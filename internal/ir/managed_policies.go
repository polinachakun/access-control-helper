package ir

// managedPolicyS3Actions maps well-known AWS managed policy ARNs to the S3
// actions they grant. Only actions within the tool's analyzable scope are
// listed (GetObject, PutObject, DeleteObject, ListBucket).
//
// Source: https://docs.aws.amazon.com/aws-managed-policy/latest/reference/
var managedPolicyS3Actions = map[string][]string{
	// Full administrative access — grants all S3 actions.
	"arn:aws:iam::aws:policy/AdministratorAccess": {
		"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
	},
	// Power user (all services except IAM management) — full S3 access.
	"arn:aws:iam::aws:policy/PowerUserAccess": {
		"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
	},
	// Full S3 access.
	"arn:aws:iam::aws:policy/AmazonS3FullAccess": {
		"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
	},
	// Read-only S3 access.
	"arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess": {
		"s3:GetObject", "s3:ListBucket",
	},
	// Broad read-only across AWS services — includes S3 reads.
	"arn:aws:iam::aws:policy/ReadOnlyAccess": {
		"s3:GetObject", "s3:ListBucket",
	},
	// Lambda execution role with S3 read/write (used for Lambda→S3 patterns).
	"arn:aws:iam::aws:policy/AWSLambdaExecute": {
		"s3:GetObject", "s3:PutObject",
	},
	// CodePipeline / CodeBuild full access — includes S3 artifact access.
	"arn:aws:iam::aws:policy/AWSCodePipelineFullAccess": {
		"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
	},
	"arn:aws:iam::aws:policy/AWSCodeBuildAdminAccess": {
		"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
	},
	// Elastic Beanstalk / Data Pipeline — broad S3 write access.
	"arn:aws:iam::aws:policy/AdministratorAccess-AWSElasticBeanstalk": {
		"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
	},
	// Athena full access — reads from S3.
	"arn:aws:iam::aws:policy/AmazonAthenaFullAccess": {
		"s3:GetObject", "s3:PutObject", "s3:ListBucket",
	},
	// Glue service role — reads/writes S3 data.
	"arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole": {
		"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
	},
}

// ManagedPolicyS3Actions returns the S3 actions granted by a well-known AWS
// managed policy ARN, or nil if the ARN is not in the catalog.
func ManagedPolicyS3Actions(arn string) []string {
	return managedPolicyS3Actions[arn]
}
