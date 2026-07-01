package ir

// managedPolicyS3Actions maps well-known AWS managed policy ARNs to the S3
// actions they grant, restricted to the 7 actions the tool analyses:
// GetObject, PutObject, DeleteObject, ListBucket,
// GetBucketVersioning, GetObjectVersion, PutObjectAcl.

var managedPolicyS3Actions = map[string][]string{
	// Full administrative access — Action:"*" covers all S3 actions.
	"arn:aws:iam::aws:policy/AdministratorAccess": {
		"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
		"s3:GetBucketVersioning", "s3:GetObjectVersion", "s3:PutObjectAcl",
	},
	// Power user (all services except IAM management) — full S3 access.
	"arn:aws:iam::aws:policy/PowerUserAccess": {
		"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
		"s3:GetBucketVersioning", "s3:GetObjectVersion", "s3:PutObjectAcl",
	},
	// Full S3 access — Action:"s3:*".
	"arn:aws:iam::aws:policy/AmazonS3FullAccess": {
		"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
		"s3:GetBucketVersioning", "s3:GetObjectVersion", "s3:PutObjectAcl",
	},
	// Read-only S3 access — includes versioning reads.
	"arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess": {
		"s3:GetObject", "s3:ListBucket",
		"s3:GetBucketVersioning", "s3:GetObjectVersion",
	},
	// Broad read-only across AWS services — includes S3 reads.
	"arn:aws:iam::aws:policy/ReadOnlyAccess": {
		"s3:GetObject", "s3:ListBucket",
		"s3:GetBucketVersioning", "s3:GetObjectVersion",
	},
	// Lambda execution role with S3 read/write (used for Lambda→S3 patterns).
	"arn:aws:iam::aws:policy/AWSLambdaExecute": {
		"s3:GetObject", "s3:PutObject",
	},
	// CodePipeline full access — includes versioning and ACL for artifact buckets.
	"arn:aws:iam::aws:policy/AWSCodePipelineFullAccess": {
		"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
		"s3:GetBucketVersioning", "s3:GetObjectVersion", "s3:PutObjectAcl",
	},
	// CodeBuild admin access — full S3 access for build artifacts.
	"arn:aws:iam::aws:policy/AWSCodeBuildAdminAccess": {
		"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
		"s3:GetBucketVersioning", "s3:GetObjectVersion", "s3:PutObjectAcl",
	},
	// Elastic Beanstalk — broad S3 write access.
	"arn:aws:iam::aws:policy/AdministratorAccess-AWSElasticBeanstalk": {
		"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
		"s3:GetBucketVersioning", "s3:GetObjectVersion", "s3:PutObjectAcl",
	},
	// Athena full access — reads and writes S3, including versioned objects.
	"arn:aws:iam::aws:policy/AmazonAthenaFullAccess": {
		"s3:GetObject", "s3:PutObject", "s3:ListBucket",
		"s3:GetBucketVersioning", "s3:GetObjectVersion",
	},
	// Glue service role — reads/writes S3 data lakes.
	"arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole": {
		"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
		"s3:GetBucketVersioning", "s3:GetObjectVersion", "s3:PutObjectAcl",
	},
}

// ManagedPolicyS3Actions returns the S3 actions granted by a well-known AWS
// managed policy ARN, or nil if the ARN is not in the catalog.
func ManagedPolicyS3Actions(arn string) []string {
	return managedPolicyS3Actions[arn]
}
