package generator

func actionLevelFacts(action string) (bucketLevel string, objectLevel string) {
	// Bucket-level actions — resource ARN: arn:aws:s3:::bucket
	switch action {
	case
		// List / discovery
		"S3_ListBucket",
		"S3_ListBucketVersions",
		"S3_ListBucketMultipartUploads",
		// Bucket lifecycle
		"S3_CreateBucket",
		"S3_DeleteBucket",
		// Bucket policy
		"S3_GetBucketPolicy",
		"S3_PutBucketPolicy",
		"S3_DeleteBucketPolicy",
		"S3_GetBucketPolicyStatus",
		// ACL
		"S3_GetBucketAcl",
		"S3_PutBucketAcl",
		// Versioning
		"S3_GetBucketVersioning",
		"S3_PutBucketVersioning",
		// Tagging
		"S3_GetBucketTagging",
		"S3_PutBucketTagging",
		"S3_DeleteBucketTagging",
		// Encryption
		"S3_GetEncryptionConfiguration",
		"S3_PutEncryptionConfiguration",
		"S3_DeleteBucketEncryption",
		// Public access block
		"S3_GetBucketPublicAccessBlock",
		"S3_PutBucketPublicAccessBlock",
		"S3_DeletePublicAccessBlock",
		// Logging
		"S3_GetBucketLogging",
		"S3_PutBucketLogging",
		// Notification
		"S3_GetBucketNotification",
		"S3_PutBucketNotification",
		// CORS
		"S3_GetBucketCORS",
		"S3_PutBucketCORS",
		"S3_DeleteBucketCORS",
		// Website
		"S3_GetBucketWebsite",
		"S3_PutBucketWebsite",
		"S3_DeleteBucketWebsite",
		// Accelerate
		"S3_GetAccelerateConfiguration",
		"S3_PutAccelerateConfiguration",
		// Request payment
		"S3_GetBucketRequestPayment",
		"S3_PutBucketRequestPayment",
		// Replication
		"S3_GetReplicationConfiguration",
		"S3_PutReplicationConfiguration",
		"S3_DeleteBucketReplication",
		// Lifecycle
		"S3_GetLifecycleConfiguration",
		"S3_PutLifecycleConfiguration",
		"S3_DeleteBucketLifecycle",
		// Intelligent tiering
		"S3_GetIntelligentTieringConfiguration",
		"S3_PutIntelligentTieringConfiguration",
		"S3_DeleteIntelligentTieringConfiguration",
		"S3_ListBucketIntelligentTieringConfigurations",
		// Inventory
		"S3_GetInventoryConfiguration",
		"S3_PutInventoryConfiguration",
		"S3_DeleteInventoryConfiguration",
		"S3_ListBucketInventoryConfigurations",
		// Analytics
		"S3_GetAnalyticsConfiguration",
		"S3_PutAnalyticsConfiguration",
		"S3_DeleteBucketAnalyticsConfiguration",
		"S3_ListBucketAnalyticsConfigurations",
		// Metrics
		"S3_GetMetricsConfiguration",
		"S3_PutMetricsConfiguration",
		"S3_DeleteBucketMetricsConfiguration",
		"S3_ListBucketMetricsConfigurations",
		// Object lock config (bucket-level)
		"S3_GetBucketObjectLockConfiguration",
		"S3_PutBucketObjectLockConfiguration",
		// Ownership controls
		"S3_GetBucketOwnershipControls",
		"S3_PutBucketOwnershipControls",
		"S3_DeleteBucketOwnershipControls",
		// Multipart uploads listing (bucket-level)
		"S3_ListMultipartUploads",
		// Location
		"S3_GetBucketLocation":
		return "True", "False"
	}

	// Object-level actions — resource ARN: arn:aws:s3:::bucket/*
	switch action {
	case
		// Core object operations
		"S3_GetObject",
		"S3_PutObject",
		"S3_DeleteObject",
		"S3_CopyObject",
		"S3_HeadObject",
		// Versions
		"S3_GetObjectVersion",
		"S3_DeleteObjectVersion",
		"S3_CopyObjectVersion",
		// ACL
		"S3_GetObjectAcl",
		"S3_PutObjectAcl",
		"S3_GetObjectVersionAcl",
		"S3_PutObjectVersionAcl",
		// Tagging
		"S3_GetObjectTagging",
		"S3_PutObjectTagging",
		"S3_DeleteObjectTagging",
		"S3_GetObjectVersionTagging",
		"S3_PutObjectVersionTagging",
		"S3_DeleteObjectVersionTagging",
		// Attributes / metadata
		"S3_GetObjectAttributes",
		"S3_GetObjectVersionAttributes",
		// Legal hold / retention
		"S3_GetObjectLegalHold",
		"S3_PutObjectLegalHold",
		"S3_GetObjectRetention",
		"S3_PutObjectRetention",
		// Restore
		"S3_RestoreObject",
		// Multipart upload (object-level parts)
		"S3_AbortMultipartUpload",
		"S3_ListMultipartUploadParts",
		"S3_CreateMultipartUpload",
		"S3_CompleteMultipartUpload",
		"S3_UploadPart",
		"S3_UploadPartCopy",
		// Torrent
		"S3_GetObjectTorrent",
		"S3_GetObjectVersionTorrent",
		// Replication (object-level — used in replication bucket policies)
		"S3_ReplicateObject",
		"S3_ReplicateDelete",
		"S3_ReplicateTags",
		"S3_GetObjectVersionForReplication",
		"S3_InitiateReplication",
		// Object Lock governance bypass
		"S3_BypassGovernanceRetention":
		return "False", "True"
	}

	// Unknown action — resource level cannot be determined statically.
	return "False", "False"
}
