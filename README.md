audit Inventory
============================
This composite performs inventory on your AWS cloud objects


## Description
This composite scans AWS services and reports on the inventory of objects found

## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws-inventory/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

**None**


## Required variables with default

### `AUDIT_AWS_INVENTORY_ALLOW_EMPTY`:
  * description: Would you like to receive empty reports? Options - true / false. Default is false.
  * default: false

### `AUDIT_AWS_INVENTORY_SEND_ON`:
  * description: Send reports always or only when there is a change? Options - always / change. Default is change.
  * default: change

### `AUDIT_AWS_INVENTORY_OWNER_TAG`:
  * description: Enter an AWS tag whose value is an email address of the owner of the AWS services being audited. (Optional)
  * default: NOT_A_TAG

### `AUDIT_AWS_INVENTORY_REGIONS`:
  * description: List of AWS regions to check. Default is all regions. Choices are us-east-1,us-east-2,us-west-1,us-west-2,ca-central-1,ap-south-1,ap-northeast-2,ap-southeast-1,ap-southeast-2,ap-northeast-1,eu-central-1,eu-west-1,eu-west-1,sa-east-1
  * default: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, ap-south-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-northeast-1, eu-central-1, eu-west-1, eu-west-2, sa-east-1


## Optional variables with default

### `AUDIT_AWS_CLOUDTRAIL_ALERT_LIST`:
  * description: Which rules would you like to run? Possible values are cloudtrail-inventory cloudtrail-service-disabled cloudtrail-log-file-validating cloudtrail-logs-cloudwatch cloudtrail-no-global-trails cloudtrail-logs-encrypted
  * default: cloudtrail-inventory

### `AUDIT_AWS_CLOUDWATCH_ALERT_LIST`:
  * description: Which rules would you like to run? Possible values are cloudwatch-inventory
  * default: cloudwatch-inventory

### `AUDIT_AWS_CLOUDWATCHLOGS_ALERT_LIST`:
  * description: Which rules would you like to run? Possible values are cloudwatchlogs-inventory
  * default: cloudwatchlogs-inventory

### `AUDIT_AWS_CONFIG_ALERT_LIST`:
  * description: Which rules would you like to run? Possible values are config-inventory config-enabled-rule
  * default: config-inventory

### `AUDIT_AWS_EC2_ALERT_LIST`:
  * description: Which rules would you like to run? Possible values are ec2-inventory-instances ec2-inventory-security-groups ec2-ip-address-whitelisted ec2-unrestricted-traffic ec2-TCP-1521-0.0.0.0/0 ec2-TCP-3306-0.0.0.0/0 ec2-TCP-5432-0.0.0.0/0 ec2-TCP-27017-0.0.0.0/0 ec2-TCP-1433-0.0.0.0/0 ec2-TCP-3389-0.0.0.0/0 ec2-TCP-22-0.0.0.0/0 ec2-TCP-5439-0.0.0.0/0 ec2-TCP-23 ec2-TCP-21 ec2-TCP-20 ec2-ports-range ec2-not-used-security-groups ec2-default-security-group-traffic ec2-vpc-flow-logs
  * default: ec2-inventory-instances, ec2-inventory-security-groups, vpc-inventory, flow-logs-inventory

### `AUDIT_AWS_ELB_ALERT_LIST`:
  * description: Which rules would you like to run? Possible values are elb-inventory elb-old-ssl-policy elb-current-ssl-policy
  * default: elb-inventory

### `AUDIT_AWS_IAM_ALERT_LIST`:
  * description: Which rules would you like to run? Possible values are iam-inventory-users iam-inventory-roles iam-inventory-policies iam-inventory-groups iam-unusediamgroup iam-multiple-keys iam-root-multiple-keys iam-inactive-key-no-rotation iam-active-key-no-rotation iam-missing-password-policy iam-passwordreuseprevention iam-expirepasswords iam-no-mfa iam-root-active-password iam-user-attached-policies iam-password-policy-uppercase iam-password-policy-lowercase iam-password-policy-symbol iam-password-policy-number iam-password-policy-min-length iam-root-access-key-1 iam-root-access-key-2 iam-cloudbleed-passwords-not-rotated iam-support-role iam-user-password-not-used iam-unused-access iam-no-hardware-mfa-root iam-active-root-user iam-mfa-password-holders manual-ensure-security-questions manual-detailed-billing iam-root-key-access iam-root-no-mfa manual-strategic-iam-roles iam-initialization-access-key manual-contact-details manual-security-contact manual-resource-instance-access manual-full-privilege-user manual-appropriate-sns-subscribers manual-least-access-routing-tables
  * default: iam-inventory-users, iam-inventory-roles, iam-inventory-policies, iam-inventory-groups

### `AUDIT_AWS_KMS_ALERT_LIST`:
  * description: Which rules would you like to run? Possible values are kms-inventory kms-key-rotates
  * default: kms-inventory

### `AUDIT_AWS_RDS_ALERT_LIST`:
  * description: Which rules would you like to run? Possible values are rds-inventory rds-short-backup-retention-period rds-no-auto-minor-version-upgrade rds-db-publicly-accessible
  * default: rds-inventory

### `AUDIT_AWS_REDSHIFT_ALERT_LIST`:
  * description: Which rules would you like to run? Possible values are redshift-inventory redshift-publicly-accessible redshift-encrypted redshift-no-version-upgrade redshift-no-require-ssl redshift-no-s3-logging redshift-no-user-logging redshift-snapshot-retention
  * default: redshift-inventory

### `AUDIT_AWS_S3_ALERT_LIST`:
  * description: Which rules would you like to run? Possible values are s3-allusers-write s3-allusers-write-acp s3-allusers-read s3-authenticatedusers-write s3-authenticatedusers-write-acp s3-authenticatedusers-read s3-logging-disabled s3-world-open-policy-delete s3-world-open-policy-get s3-world-open-policy-list s3-world-open-policy-put s3-world-open-policy-all s3-only-ip-based-policy
  * default: s3-inventory

### `AUDIT_AWS_SNS_ALERT_LIST`:
  * description: Which rules would you like to run? Possible values are sns-topics-inventory sns-subscriptions-inventory
  * default: sns-topics-inventory, sns-subscriptions-inventory


## Optional variables with no default

### `HTML_REPORT_SUBJECT`:
  * description: Enter a custom report subject name.

### `AUDIT_AWS_INVENTORY_ALERT_RECIPIENT`:
  * description: Enter the email address(es) that will receive notifications. If more than one, separate each with a comma.

## Tags
1. Inventory

## Categories
1. AWS Inventory



## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/audit-aws-inventory/master/images/diagram.png "diagram")


## Icon
![icon](https://raw.githubusercontent.com/CloudCoreo/audit-aws-inventory/master/images/icon.png "icon")

