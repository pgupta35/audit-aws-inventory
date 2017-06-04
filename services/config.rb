# ACM
#   - list_certificates
#     - id: certificate_summary_list.certificate_arn
# APIGateway
#   - get_api_keys
#     - id: items.id
#   - get_client_certificates
#     - id: items.client_certificate_id
#   - get_domain_names
#     - id: items.certificate_arn
#   - get_rest_apis
#     - id: items.id
#   - get_sdk_types
#     - id: items.id
#   - get_usage_plans
#     - id: items.id
# AppStream
#   - describe_images
#     - id: images.arn
#   - describe_fleets
#     - id: fleets.arn
#   - describe_stacks
#     - id: stacks.arn
# ApplicationAutoScaling
# ApplicationDiscoveryService
# AutoScaling
#   - describe_scaling_activities
#     - id: activities.activity_id
#   - describe_account_limits
#     - id: NA
#   - describe_adjustment_types
#     - id: NA
#   - describe_auto_scaling_groups
#     - id: auto_scaling_groups.auto_scaling_group_arn
#   - describe_auto_scaling_instances
#     - id: auto_scaling_instances.instance_id
#   - describe_auto_scaling_notification_types
#     - id: NA
#   - describe_launch_configurations
#     - id: launch_configurations.launch_configuration_arn
#   - describe_lifecycle_hook_types
#     - id: NA
#   - describe_metric_collection_types
#     - id: NA
#   - describe_notification_configurations
#     - id: notification_configurations.topic_arn
#   - describe_policies
#     - id: scaling_policies.policy_arn
#   - describe_scaling_process_types
#     - id: processes.process_name
#   - describe_scheduled_actions
#     - id: scheduled_update_group_actions.scheduled_action_arn
#   - describe_termination_policy_types
#     - id: NA
# Batch
#   - describe_compute_environments
#     - id: compute_environments.compute_environment_arn
#   - describe_job_definitions
#     - id: job_definitions.job_definition_arn
#   - describe_job_queues
#     - id: job_queues.job_queue_arn
# Budgets
# CloudDirectory
#   - list_development_schema_arns
#     - id: NA
#   - list_directories
#     - id: directories.directory_arn
#   - list_published_schema_arns
#     - id: NA
# CloudFormation
#   - describe_stacks
#     - id: stacks.role_arn
#   - describe_account_limits
#     - id: NA
#   - list_exports
#     - id: exports.exporting_stack_id
#   - list_stacks
#     - id: stack_summaries.stack_id
# CloudFront
#   - list_cloud_front_origin_access_identities
#     - id: cloud_front_origin_access_identity_list.items.id
#   - list_distributions
#     - id: distribution_list.items.arn
#   - list_streaming_distributions
#     - id: streaming_distribution_list.items.arn
# CloudHSM
#   - list_available_zones
#     - id: NA
#   - list_hapgs
#     - id: NA
#   - list_hsms
#     - id: NA
#   - list_luna_clients
#     - id: NA
# CloudSearch
#   - describe_domains
#     - id: domain_status_list.arn
#   - list_domain_names
#     - id: NA
# CloudSearchDomain
# CloudTrail
#   - describe_trails
#     - id: trail_list.cloud_watch_logs_role_arn
#   - list_public_keys
#     - id: NA
# CloudWatch
#   - describe_alarms
#     - id: metric_alarms.alarm_arn
#   - list_metrics
#     - id: metrics.metric_name
# CloudWatchEvents
#   - list_rules
#     - id: rules.arn
# CloudWatchLogs
#   - describe_export_tasks
#     - id: export_tasks.task_id
#   - describe_destinations
#     - id: destinations.target_arn
#   - describe_log_groups
#     - id: log_groups.arn
#   - describe_metric_filters
#     - id: metric_filters.filter_name
# CodeBuild
#   - list_builds
#     - id: [/arn\b/, /\.id/, /_id\b/, /_name\b/, /\[\0\]\b/]
#   - list_curated_environment_images
#     - id: NA
#   - list_projects
#     - id: NA
# CodeCommit
#   - list_repositories
#     - id: repositories.repository_id
# CodeDeploy
#   - list_applications
#     - id: NA
#   - list_deployment_configs
#     - id: NA
#   - list_deployments
#     - id: NA
#   - list_on_premises_instances
#     - id: NA
# CodePipeline
#   - list_action_types
#     - id: action_types.id.category
#   - list_pipelines
#     - id: NA
# CodeStar
#   - list_projects
#     - id: projects.project_arn
#   - list_user_profiles
#     - id: user_profiles.user_arn
# CognitoIdentity
# CognitoIdentityProvider
# ACM
# APIGateway
# AppStream
# ApplicationAutoScaling
# ApplicationDiscoveryService
# AutoScaling
# Batch
# Budgets
# CloudDirectory
# CloudFormation
# CloudFront
# CloudHSM
# CloudSearch
# CloudSearchDomain
# CloudTrail
# CloudWatch
# CloudWatchEvents
# CloudWatchLogs
# CodeBuild
#   - list_builds
#     - id: [/arn\b/, /\.id/, /_id\b/, /_name\b/, /\[\0\]\b/]
#   - list_curated_environment_images
#     - id: NA
#   - list_projects
#     - id: NA
# CodeCommit
# CodeDeploy
# CodePipeline
# CodeStar
# CognitoIdentity
# CognitoIdentityProvider
# CognitoSync
# ConfigService
# CostandUsageReportService
# DataPipeline
# DatabaseMigrationService
# DeviceFarm
# DirectConnect
# DirectoryService
# DynamoDB
# DynamoDBStreams
# EC2
# ECR
# ECS
# EFS
# EMR
# ElastiCache
# ElasticBeanstalk
# ElasticLoadBalancing
# ElasticLoadBalancingV2
# ElasticTranscoder
# ElasticsearchService
# Firehose
# GameLift
# Glacier
# Health
# IAM
# ImportExport
# Inspector
# IoT
# IoTDataPlane
# KMS
# Kinesis
# KinesisAnalytics
# Lambda
# LambdaPreview
# Lex
# LexModelBuildingService
# Lightsail
# MTurk
# MachineLearning
# MarketplaceCommerceAnalytics
# MarketplaceMetering
# OpsWorks
# OpsWorksCM
# Organizations
# Pinpoint
# Polly
# RDS
# Redshift
# Rekognition
# ResourceGroupsTaggingAPI
# Route53
# Route53Domains
# S3
# SES
# SMS
# SNS
# SQS
# SSM
# STS
# SWF
# ServiceCatalog
# Shield
# SimpleDB
# Snowball
# States
# StorageGateway
# Support
# WAF
# WAFRegional
# WorkDocs
# WorkSpaces
# XRay
coreo_aws_rule "codebuild-inventory-builds" do
  service :CodeBuild
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeBuild Inventory"
  description "This rule performs an inventory on the CodeBuild service using the list_builds function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_builds"]
  audit_objects ["object.[/arn\b/, /\.id/, /_id\b/, /_name\b/, /\[\0\]\b/]"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.[/arn\b/, /\.id/, /_id\b/, /_name\b/, /\[\0\]\b/]"]
end
  
coreo_aws_rule_runner "codebuild-inventory-runner" do
  action :run
  service :CodeBuild
  rules ${AUDIT_AWS_CODEBUILD_ALERT_LIST}
end
# ACM
# APIGateway
# AppStream
# ApplicationAutoScaling
# ApplicationDiscoveryService
# AutoScaling
# Batch
# Budgets
# CloudDirectory
# CloudFormation
# CloudFront
# CloudHSM
# CloudSearch
# CloudSearchDomain
# CloudTrail
# CloudWatch
# CloudWatchEvents
# CloudWatchLogs
# CodeBuild
#   - list_builds
#     - id: [/arn\b/, /\.id/, /_id\b/, /_name\b/, /\[\0\]\b/]
#   - list_curated_environment_images
#     - id: NA
# CodeCommit
# CodeDeploy
# CodePipeline
# CodeStar
# CognitoIdentity
# CognitoIdentityProvider
# CognitoSync
# ConfigService
# CostandUsageReportService
# DataPipeline
# DatabaseMigrationService
# DeviceFarm
# DirectConnect
# DirectoryService
# DynamoDB
# DynamoDBStreams
# EC2
# ECR
# ECS
# EFS
# EMR
# ElastiCache
# ElasticBeanstalk
# ElasticLoadBalancing
# ElasticLoadBalancingV2
# ElasticTranscoder
# ElasticsearchService
# Firehose
# GameLift
# Glacier
# Health
# IAM
# ImportExport
# Inspector
# IoT
# IoTDataPlane
# KMS
# Kinesis
# KinesisAnalytics
# Lambda
# LambdaPreview
# Lex
# LexModelBuildingService
# Lightsail
# MTurk
# MachineLearning
# MarketplaceCommerceAnalytics
# MarketplaceMetering
# OpsWorks
# OpsWorksCM
# Organizations
# Pinpoint
# Polly
# RDS
# Redshift
# Rekognition
# ResourceGroupsTaggingAPI
# Route53
# Route53Domains
# S3
# SES
# SMS
# SNS
# SQS
# SSM
# STS
# SWF
# ServiceCatalog
# Shield
# SimpleDB
# Snowball
# States
# StorageGateway
# Support
# WAF
# WAFRegional
# WorkDocs
# WorkSpaces
# XRay
coreo_aws_rule "codebuild-inventory-builds" do
  service :CodeBuild
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeBuild Inventory"
  description "This rule performs an inventory on the CodeBuild service using the list_builds function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_builds"]
  audit_objects ["object.[/arn\b/, /\.id/, /_id\b/, /_name\b/, /\[\0\]\b/]"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.[/arn\b/, /\.id/, /_id\b/, /_name\b/, /\[\0\]\b/]"]
end
  
coreo_aws_rule_runner "codebuild-inventory-runner" do
  action :run
  service :CodeBuild
  rules ${AUDIT_AWS_CODEBUILD_ALERT_LIST}
end
# ACM
# APIGateway
# AppStream
# ApplicationAutoScaling
# ApplicationDiscoveryService
# AutoScaling
# Batch
# Budgets
# CloudDirectory
# CloudFormation
# CloudFront
# CloudHSM
# CloudSearch
# CloudSearchDomain
# CloudTrail
# CloudWatch
# CloudWatchEvents
# CloudWatchLogs
# CodeBuild
#   - list_builds
#     - id: [/arn\b/, /\.id/, /_id\b/, /_name\b/, /\[\0\]\b/]
#   - list_curated_environment_images
#     - id: NA
#   - list_projects
#     - id: NA
# CodeCommit
# CodeDeploy
# CodePipeline
# CodeStar
# CognitoIdentity
# CognitoIdentityProvider
# CognitoSync
# ConfigService
# CostandUsageReportService
# DataPipeline
# DatabaseMigrationService
# DeviceFarm
# DirectConnect
# DirectoryService
# DynamoDB
# DynamoDBStreams
# EC2
# ECR
# ECS
# EFS
# EMR
# ElastiCache
# ElasticBeanstalk
# ElasticLoadBalancing
# ElasticLoadBalancingV2
# ElasticTranscoder
# ElasticsearchService
# Firehose
# GameLift
# Glacier
# Health
# IAM
# ImportExport
# Inspector
# IoT
# IoTDataPlane
# KMS
# Kinesis
# KinesisAnalytics
# Lambda
# LambdaPreview
# Lex
# LexModelBuildingService
# Lightsail
# MTurk
# MachineLearning
# MarketplaceCommerceAnalytics
# MarketplaceMetering
# OpsWorks
# OpsWorksCM
# Organizations
# Pinpoint
# Polly
# RDS
# Redshift
# Rekognition
# ResourceGroupsTaggingAPI
# Route53
# Route53Domains
# S3
# SES
# SMS
# SNS
# SQS
# SSM
# STS
# SWF
# ServiceCatalog
# Shield
# SimpleDB
# Snowball
# States
# StorageGateway
# Support
# WAF
# WAFRegional
# WorkDocs
# WorkSpaces
# XRay
coreo_aws_rule "codebuild-inventory-builds" do
  service :CodeBuild
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeBuild Inventory"
  description "This rule performs an inventory on the CodeBuild service using the list_builds function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_builds"]
  audit_objects ["object.[/arn\b/, /\.id/, /_id\b/, /_name\b/, /\[\0\]\b/]"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.[/arn\b/, /\.id/, /_id\b/, /_name\b/, /\[\0\]\b/]"]
end
  
coreo_aws_rule_runner "codebuild-inventory-runner" do
  action :run
  service :CodeBuild
  rules ${AUDIT_AWS_CODEBUILD_ALERT_LIST}
end
# ACM
# APIGateway
# AppStream
# ApplicationAutoScaling
# ApplicationDiscoveryService
# AutoScaling
# Batch
# Budgets
# CloudDirectory
# CloudFormation
# CloudFront
# CloudHSM
# CloudSearch
# CloudSearchDomain
# CloudTrail
# CloudWatch
# CloudWatchEvents
# CloudWatchLogs
# CodeBuild
#   - list_builds
#     - id: [/arn\b/, /\.id/, /_id\b/, /_name\b/, /\[\0\]\b/]
# CodeCommit
# CodeDeploy
# CodePipeline
# CodeStar
# CognitoIdentity
# CognitoIdentityProvider
# CognitoSync
# ConfigService
# CostandUsageReportService
# DataPipeline
# DatabaseMigrationService
# DeviceFarm
# DirectConnect
# DirectoryService
# DynamoDB
# DynamoDBStreams
# EC2
# ECR
# ECS
# EFS
# EMR
# ElastiCache
# ElasticBeanstalk
# ElasticLoadBalancing
# ElasticLoadBalancingV2
# ElasticTranscoder
# ElasticsearchService
# Firehose
# GameLift
# Glacier
# Health
# IAM
# ImportExport
# Inspector
# IoT
# IoTDataPlane
# KMS
# Kinesis
# KinesisAnalytics
# Lambda
# LambdaPreview
# Lex
# LexModelBuildingService
# Lightsail
# MTurk
# MachineLearning
# MarketplaceCommerceAnalytics
# MarketplaceMetering
# OpsWorks
# OpsWorksCM
# Organizations
# Pinpoint
# Polly
# RDS
# Redshift
# Rekognition
# ResourceGroupsTaggingAPI
# Route53
# Route53Domains
# S3
# SES
# SMS
# SNS
# SQS
# SSM
# STS
# SWF
# ServiceCatalog
# Shield
# SimpleDB
# Snowball
# States
# StorageGateway
# Support
# WAF
# WAFRegional
# WorkDocs
# WorkSpaces
# XRay
coreo_aws_rule "codebuild-inventory-builds" do
  service :CodeBuild
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeBuild Inventory"
  description "This rule performs an inventory on the CodeBuild service using the list_builds function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_builds"]
  audit_objects ["object.[/arn\b/, /\.id/, /_id\b/, /_name\b/, /\[\0\]\b/]"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.[/arn\b/, /\.id/, /_id\b/, /_name\b/, /\[\0\]\b/]"]
end
  
coreo_aws_rule_runner "codebuild-inventory-runner" do
  action :run
  service :CodeBuild
  rules ${AUDIT_AWS_CODEBUILD_ALERT_LIST}
end
# ACM
# APIGateway
# AppStream
# ApplicationAutoScaling
# ApplicationDiscoveryService
# AutoScaling
# Batch
# Budgets
# CloudDirectory
# CloudFormation
# CloudFront
# CloudHSM
# CloudSearch
# CloudSearchDomain
# CloudTrail
# CloudWatch
# CloudWatchEvents
# CloudWatchLogs
# CodeBuild
#   - list_builds
#     - id: NA
# CodeCommit
# CodeDeploy
# CodePipeline
# CodeStar
# CognitoIdentity
# CognitoIdentityProvider
# CognitoSync
# ConfigService
# CostandUsageReportService
# DataPipeline
# DatabaseMigrationService
# DeviceFarm
# DirectConnect
# DirectoryService
# DynamoDB
# DynamoDBStreams
# EC2
# ECR
# ECS
# EFS
# EMR
# ElastiCache
# ElasticBeanstalk
# ElasticLoadBalancing
# ElasticLoadBalancingV2
# ElasticTranscoder
# ElasticsearchService
# Firehose
# GameLift
# Glacier
# Health
# IAM
# ImportExport
# Inspector
# IoT
# IoTDataPlane
# KMS
# Kinesis
# KinesisAnalytics
# Lambda
# LambdaPreview
# Lex
# LexModelBuildingService
# Lightsail
# MTurk
# MachineLearning
# MarketplaceCommerceAnalytics
# MarketplaceMetering
# OpsWorks
# OpsWorksCM
# Organizations
# Pinpoint
# Polly
# RDS
# Redshift
# Rekognition
# ResourceGroupsTaggingAPI
# Route53
# Route53Domains
# S3
# SES
# SMS
# SNS
# SQS
# SSM
# STS
# SWF
# ServiceCatalog
# Shield
# SimpleDB
# Snowball
# States
# StorageGateway
# Support
# WAF
# WAFRegional
# WorkDocs
# WorkSpaces
# XRay
  
coreo_aws_rule_runner "codebuild-inventory-runner" do
  action :run
  service :CodeBuild
  rules ${AUDIT_AWS_CODEBUILD_ALERT_LIST}
end
# ACM
# APIGateway
# AppStream
# ApplicationAutoScaling
# ApplicationDiscoveryService
# AutoScaling
# Batch
# Budgets
# CloudDirectory
# CloudFormation
# CloudFront
# CloudHSM
# CloudSearch
# CloudSearchDomain
# CloudTrail
# CloudWatch
# CloudWatchEvents
# CloudWatchLogs
# CodeBuild
#   - list_builds
#     - id: NA
#   - list_curated_environment_images
#     - id: NA
#   - list_projects
#     - id: NA
# CodeCommit
# CodeDeploy
# CodePipeline
# CodeStar
# CognitoIdentity
# CognitoIdentityProvider
# CognitoSync
# ConfigService
# CostandUsageReportService
# DataPipeline
# DatabaseMigrationService
# DeviceFarm
# DirectConnect
# DirectoryService
# DynamoDB
# DynamoDBStreams
# EC2
# ECR
# ECS
# EFS
# EMR
# ElastiCache
# ElasticBeanstalk
# ElasticLoadBalancing
# ElasticLoadBalancingV2
# ElasticTranscoder
# ElasticsearchService
# Firehose
# GameLift
# Glacier
# Health
# IAM
# ImportExport
# Inspector
# IoT
# IoTDataPlane
# KMS
# Kinesis
# KinesisAnalytics
# Lambda
# LambdaPreview
# Lex
# LexModelBuildingService
# Lightsail
# MTurk
# MachineLearning
# MarketplaceCommerceAnalytics
# MarketplaceMetering
# OpsWorks
# OpsWorksCM
# Organizations
# Pinpoint
# Polly
# RDS
# Redshift
# Rekognition
# ResourceGroupsTaggingAPI
# Route53
# Route53Domains
# S3
# SES
# SMS
# SNS
# SQS
# SSM
# STS
# SWF
# ServiceCatalog
# Shield
# SimpleDB
# Snowball
# States
# StorageGateway
# Support
# WAF
# WAFRegional
# WorkDocs
# WorkSpaces
# XRay
  
coreo_aws_rule_runner "codebuild-inventory-runner" do
  action :run
  service :CodeBuild
  rules ${AUDIT_AWS_CODEBUILD_ALERT_LIST}
end
# ACM
# APIGateway
# AppStream
# ApplicationAutoScaling
# ApplicationDiscoveryService
# AutoScaling
# Batch
# Budgets
# CloudDirectory
# CloudFormation
# CloudFront
# CloudHSM
# CloudSearch
# CloudSearchDomain
# CloudTrail
# CloudWatch
# CloudWatchEvents
# CloudWatchLogs
# CodeBuild
#   - list_builds
#     - id: NA
# CodeCommit
# CodeDeploy
# CodePipeline
# CodeStar
# CognitoIdentity
# CognitoIdentityProvider
# CognitoSync
# ConfigService
# CostandUsageReportService
# DataPipeline
# DatabaseMigrationService
# DeviceFarm
# DirectConnect
# DirectoryService
# DynamoDB
# DynamoDBStreams
# EC2
# ECR
# ECS
# EFS
# EMR
# ElastiCache
# ElasticBeanstalk
# ElasticLoadBalancing
# ElasticLoadBalancingV2
# ElasticTranscoder
# ElasticsearchService
# Firehose
# GameLift
# Glacier
# Health
# IAM
# ImportExport
# Inspector
# IoT
# IoTDataPlane
# KMS
# Kinesis
# KinesisAnalytics
# Lambda
# LambdaPreview
# Lex
# LexModelBuildingService
# Lightsail
# MTurk
# MachineLearning
# MarketplaceCommerceAnalytics
# MarketplaceMetering
# OpsWorks
# OpsWorksCM
# Organizations
# Pinpoint
# Polly
# RDS
# Redshift
# Rekognition
# ResourceGroupsTaggingAPI
# Route53
# Route53Domains
# S3
# SES
# SMS
# SNS
# SQS
# SSM
# STS
# SWF
# ServiceCatalog
# Shield
# SimpleDB
# Snowball
# States
# StorageGateway
# Support
# WAF
# WAFRegional
# WorkDocs
# WorkSpaces
# XRay
  
coreo_aws_rule_runner "codebuild-inventory-runner" do
  action :run
  service :CodeBuild
  rules ${AUDIT_AWS_CODEBUILD_ALERT_LIST}
end
# ACM
# APIGateway
# AppStream
# ApplicationAutoScaling
# ApplicationDiscoveryService
# AutoScaling
# Batch
# Budgets
# CloudDirectory
# CloudFormation
# CloudFront
# CloudHSM
# CloudSearch
# CloudSearchDomain
# CloudTrail
# CloudWatch
# CloudWatchEvents
# CloudWatchLogs
# CodeBuild
#   - list_builds
#     - id: ids
#   - list_curated_environment_images
#     - id: platforms.platform
#   - list_projects
#     - id: projects
# CodeCommit
# CodeDeploy
# CodePipeline
# CodeStar
# CognitoIdentity
# CognitoIdentityProvider
# CognitoSync
# ConfigService
# CostandUsageReportService
# DataPipeline
# DatabaseMigrationService
# DeviceFarm
# DirectConnect
# DirectoryService
# DynamoDB
# DynamoDBStreams
# EC2
# ECR
# ECS
# EFS
# EMR
# ElastiCache
# ElasticBeanstalk
# ElasticLoadBalancing
# ElasticLoadBalancingV2
# ElasticTranscoder
# ElasticsearchService
# Firehose
# GameLift
# Glacier
# Health
# IAM
# ImportExport
# Inspector
# IoT
# IoTDataPlane
# KMS
# Kinesis
# KinesisAnalytics
# Lambda
# LambdaPreview
# Lex
# LexModelBuildingService
# Lightsail
# MTurk
# MachineLearning
# MarketplaceCommerceAnalytics
# MarketplaceMetering
# OpsWorks
# OpsWorksCM
# Organizations
# Pinpoint
# Polly
# RDS
# Redshift
# Rekognition
# ResourceGroupsTaggingAPI
# Route53
# Route53Domains
# S3
# SES
# SMS
# SNS
# SQS
# SSM
# STS
# SWF
# ServiceCatalog
# Shield
# SimpleDB
# Snowball
# States
# StorageGateway
# Support
# WAF
# WAFRegional
# WorkDocs
# WorkSpaces
# XRay
coreo_aws_rule "codebuild-inventory-builds" do
  service :CodeBuild
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeBuild Inventory"
  description "This rule performs an inventory on the CodeBuild service using the list_builds function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_builds"]
  audit_objects ["object.ids"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.ids"]
end
coreo_aws_rule "codebuild-inventory-curated_environment_images" do
  service :CodeBuild
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeBuild Inventory"
  description "This rule performs an inventory on the CodeBuild service using the list_curated_environment_images function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_curated_environment_images"]
  audit_objects ["object.platforms.platform"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.platforms.platform"]
end
coreo_aws_rule "codebuild-inventory-projects" do
  service :CodeBuild
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeBuild Inventory"
  description "This rule performs an inventory on the CodeBuild service using the list_projects function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_projects"]
  audit_objects ["object.projects"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.projects"]
end
  
coreo_aws_rule_runner "codebuild-inventory-runner" do
  action :run
  service :CodeBuild
  rules ${AUDIT_AWS_CODEBUILD_ALERT_LIST}
end
