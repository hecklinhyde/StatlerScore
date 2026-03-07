import boto3
import json
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta

# Ports that should never be open to 0.0.0.0/0 — each has caused real breaches
SENSITIVE_PORTS = {22, 3389, 1433, 3306, 5432, 27017, 6379, 9200}

# Instance families that predate Nitro and lack modern security/performance features.
# t2 is included — it's 2014 vintage, no Nitro, and AWS actively encourages migration.
OLD_GEN_FAMILIES = {
    't1', 't2',
    'm1', 'm2', 'm3', 'm4',
    'c1', 'c3', 'c4',
    'r3', 'r4',
    'i2', 'd2', 'hs1', 'g2',
}

# EKS Kubernetes versions currently receiving AWS support and CVE patches.
# AWS maintains the 4 most recent minor versions; anything older is end-of-life.
# Update this set whenever AWS releases a new minor version or retires an old one.
EKS_SUPPORTED_VERSIONS = {'1.29', '1.30', '1.31', '1.32'}


class CloudHarvester:
    def __init__(self, session=None):
        """
        Pass a boto3.Session to use specific credentials/region.
        Falls back to boto3's default credential chain if session is None.
        """
        mk = session.client if session else boto3.client
        self.s3             = mk('s3')
        self.iam            = mk('iam')
        self.ct             = mk('cloudtrail')
        self.acc            = mk('account')
        self.cw             = mk('cloudwatch')
        self.cfg            = mk('config')
        self.ec2            = mk('ec2')
        self.gd             = mk('guardduty')
        self.backup         = mk('backup')
        self.autoscaling    = mk('autoscaling')
        self.cf             = mk('cloudfront')
        self.rds            = mk('rds')
        self.accessanalyzer = mk('accessanalyzer')
        self.securityhub    = mk('securityhub')
        self.eks            = mk('eks')

    def collect(self):
        evidence = {
            "security":               {},
            "reliability":            {},
            "operational_excellence": {},
            "performance_efficiency": {},
        }

        # Fetch shared resources up front to avoid redundant API calls
        trails       = self.ct.describe_trails()['trailList']
        buckets      = self.s3.list_buckets()['Buckets']
        totalBuckets = len(buckets)

        try:
            reservations = self.ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )['Reservations']
            allInstances = [i for r in reservations for i in r['Instances']]
        except ClientError:
            allInstances = []

        try:
            rdsInstances = self.rds.describe_db_instances()['DBInstances']
        except ClientError:
            rdsInstances = []

        # ── Security ─────────────────────────────────────────────────────────────

        summary = self.iam.get_account_summary()
        evidence["security"]["root_mfa_enabled"] = (
            summary['SummaryMap'].get('AccountMFAEnabled', 0) == 1
        )

        try:
            self.iam.get_account_password_policy()
            evidence["security"]["password_policy_set"] = True
        except self.iam.exceptions.NoSuchEntityException:
            evidence["security"]["password_policy_set"] = False

        # Ratio of buckets that aren't fully public-access-blocked
        publicCount = 0
        for b in buckets:
            try:
                blk = self.s3.get_public_access_block(Bucket=b['Name'])
                if not all(blk['PublicAccessBlockConfiguration'].values()):
                    publicCount += 1
            except ClientError:
                publicCount += 1  # no block config = treat as public
        evidence["security"]["s3_public_bucket_ratio"] = (
            publicCount / totalBuckets if totalBuckets else 0.0
        )

        try:
            detectors = self.gd.list_detectors()['DetectorIds']
            evidence["security"]["guardduty_enabled"] = len(detectors) > 0
        except ClientError:
            evidence["security"]["guardduty_enabled"] = False

        # Ratio of access keys older than 90 days (lower = better)
        try:
            users  = self.iam.list_users()['Users']
            cutoff = datetime.now(timezone.utc) - timedelta(days=90)
            totalKeys, staleKeys = 0, 0
            for user in users:
                keys = self.iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
                for key in keys:
                    totalKeys += 1
                    if key['CreateDate'] < cutoff:
                        staleKeys += 1
            evidence["security"]["stale_access_key_ratio"] = (
                staleKeys / totalKeys if totalKeys else 0.0
            )
        except ClientError:
            evidence["security"]["stale_access_key_ratio"] = 0.0

        try:
            mfaDevices   = self.iam.list_virtual_mfa_devices()['VirtualMFADevices']
            usersWithMfa = sum(1 for d in mfaDevices if 'User' in d)
            totalUsers   = len(self.iam.list_users()['Users'])
            evidence["security"]["iam_user_mfa_ratio"] = (
                usersWithMfa / totalUsers if totalUsers else 1.0
            )
        except ClientError:
            evidence["security"]["iam_user_mfa_ratio"] = 0.0

        # IMDSv2 — every instance allowing IMDSv1 is a potential SSRF-to-credential-theft path
        # (this is how the Capital One breach worked)
        if allInstances:
            imdsv2Count = sum(
                1 for i in allInstances
                if i.get('MetadataOptions', {}).get('HttpTokens') == 'required'
            )
            evidence["security"]["imdsv2_enforced_ratio"] = imdsv2Count / len(allInstances)
        else:
            evidence["security"]["imdsv2_enforced_ratio"] = 1.0

        # Security groups with sensitive ports open to 0.0.0.0/0
        try:
            sgs        = self.ec2.describe_security_groups()['SecurityGroups']
            openSgCount = 0
            for sg in sgs:
                for perm in sg.get('IpPermissions', []):
                    fromPort = perm.get('FromPort', 0)
                    toPort   = perm.get('ToPort', 65535)
                    hitsSensitive = any(
                        p in range(fromPort, toPort + 1) for p in SENSITIVE_PORTS
                    )
                    if not hitsSensitive:
                        continue
                    openToWorld = (
                        any(r['CidrIp']   == '0.0.0.0/0' for r in perm.get('IpRanges',   [])) or
                        any(r['CidrIpv6'] == '::/0'       for r in perm.get('Ipv6Ranges', []))
                    )
                    if openToWorld:
                        openSgCount += 1
                        break
            evidence["security"]["open_security_group_count"] = openSgCount
        except ClientError:
            evidence["security"]["open_security_group_count"] = 0

        if rdsInstances:
            publicRds = sum(1 for i in rdsInstances if i.get('PubliclyAccessible'))
            evidence["security"]["rds_public_instance_ratio"] = publicRds / len(rdsInstances)
        else:
            evidence["security"]["rds_public_instance_ratio"] = 0.0

        try:
            result = self.ec2.get_ebs_encryption_by_default()
            evidence["security"]["ebs_encryption_by_default"] = result['EbsEncryptionByDefault']
        except ClientError:
            evidence["security"]["ebs_encryption_by_default"] = False

        try:
            vpcs      = self.ec2.describe_vpcs()['Vpcs']
            flowLogs  = self.ec2.describe_flow_logs()['FlowLogs']
            loggedIds = {fl['ResourceId'] for fl in flowLogs}
            vpcIds    = {v['VpcId'] for v in vpcs}
            evidence["security"]["vpc_flow_logs_ratio"] = (
                len(vpcIds & loggedIds) / len(vpcIds) if vpcIds else 1.0
            )
        except ClientError:
            evidence["security"]["vpc_flow_logs_ratio"] = 0.0

        # Catches unintentional cross-account S3/KMS/role exposure
        try:
            analyzers = self.accessanalyzer.list_analyzers()['analyzers']
            evidence["security"]["access_analyzer_active"] = any(
                a['status'] == 'ACTIVE' for a in analyzers
            )
        except ClientError:
            evidence["security"]["access_analyzer_active"] = False

        # Customer-managed policies with Action:* + Resource:* — top finding in cloud pentests
        try:
            policies      = self.iam.list_policies(Scope='Local', OnlyAttached=True)['Policies']
            wildcardCount = 0
            for policy in policies[:50]:  # cap to avoid rate limiting
                doc = self.iam.get_policy_version(
                    PolicyArn=policy['Arn'],
                    VersionId=policy['DefaultVersionId']
                )['PolicyVersion']['Document']
                for stmt in doc.get('Statement', []):
                    action   = stmt.get('Action',   '')
                    resource = stmt.get('Resource', '')
                    if (stmt.get('Effect') == 'Allow' and
                            action   in ('*', ['*']) and
                            resource in ('*', ['*'])):
                        wildcardCount += 1
                        break
            evidence["security"]["iam_wildcard_admin_count"] = wildcardCount
        except ClientError:
            evidence["security"]["iam_wildcard_admin_count"] = 0

        # Versioning is the primary ransomware defence for S3
        try:
            versioned = sum(
                1 for b in buckets
                if self.s3.get_bucket_versioning(Bucket=b['Name']).get('Status') == 'Enabled'
            )
            evidence["security"]["s3_versioning_ratio"] = (
                versioned / totalBuckets if totalBuckets else 1.0
            )
        except ClientError:
            evidence["security"]["s3_versioning_ratio"] = 0.0

        # Buckets without a TLS-enforcing policy allow unencrypted HTTP requests.
        # The fix is a Deny statement conditioned on aws:SecureTransport = false.
        tlsEnforced = 0
        for b in buckets:
            try:
                policy = json.loads(self.s3.get_bucket_policy(Bucket=b['Name'])['Policy'])
                for stmt in policy.get('Statement', []):
                    condition = stmt.get('Condition', {}).get('Bool', {})
                    deniesHttp = (
                        stmt.get('Effect') == 'Deny' and
                        condition.get('aws:SecureTransport') in ('false', False)
                    )
                    if deniesHttp:
                        tlsEnforced += 1
                        break
            except ClientError:
                pass  # no policy = HTTP not denied
        evidence["security"]["s3_tls_enforced_ratio"] = (
            tlsEnforced / totalBuckets if totalBuckets else 1.0
        )

        # ACLs are a legacy access mechanism that AWS recommends disabling entirely.
        # Setting BucketOwnerEnforced removes them and prevents ACL-based public exposure.
        aclDisabled = 0
        for b in buckets:
            try:
                controls = self.s3.get_bucket_ownership_controls(Bucket=b['Name'])
                rules    = controls.get('OwnershipControls', {}).get('Rules', [])
                if any(r.get('ObjectOwnership') == 'BucketOwnerEnforced' for r in rules):
                    aclDisabled += 1
            except ClientError:
                pass  # no ownership controls set = ACLs potentially active
        evidence["security"]["s3_acl_disabled_ratio"] = (
            aclDisabled / totalBuckets if totalBuckets else 1.0
        )

        # Security Hub aggregates findings from GuardDuty, Inspector, Macie, etc.
        try:
            self.securityhub.describe_hub()
            evidence["security"]["security_hub_enabled"] = True
        except ClientError:
            evidence["security"]["security_hub_enabled"] = False

        # Deprecated AMIs no longer receive security patches — running one is equivalent
        # to running a permanently unpatched OS
        try:
            amiIds = list({i['ImageId'] for i in allInstances})[:100]  # cap API call
            if amiIds:
                images           = self.ec2.describe_images(ImageIds=amiIds)['Images']
                now              = datetime.now(timezone.utc)
                deprecatedCount  = sum(
                    1 for img in images
                    if img.get('DeprecationTime') and
                    datetime.fromisoformat(img['DeprecationTime'].replace('Z', '+00:00')) < now
                )
                evidence["security"]["deprecated_ami_ratio"] = deprecatedCount / len(amiIds)
            else:
                evidence["security"]["deprecated_ami_ratio"] = 0.0
        except ClientError:
            evidence["security"]["deprecated_ami_ratio"] = 0.0

        # Public RDS snapshots have caused several high-profile database dumps
        try:
            manualSnaps = self.rds.describe_db_snapshots(SnapshotType='manual')['DBSnapshots']
            publicSnaps = 0
            for snap in manualSnaps[:20]:  # cap to avoid rate limiting
                attrs = self.rds.describe_db_snapshot_attributes(
                    DBSnapshotIdentifier=snap['DBSnapshotIdentifier']
                )['DBSnapshotAttributesResult']['DBSnapshotAttributes']
                if any(
                    a['AttributeName'] == 'restore' and 'all' in a['AttributeValues']
                    for a in attrs
                ):
                    publicSnaps += 1
            evidence["security"]["rds_public_snapshot_count"] = publicSnaps
        except ClientError:
            evidence["security"]["rds_public_snapshot_count"] = 0

        # ── Reliability ───────────────────────────────────────────────────────────

        evidence["reliability"]["cloudtrail_enabled"]     = len(trails) > 0
        evidence["reliability"]["cloudtrail_multiregion"] = any(
            t.get('IsMultiRegionTrail', False) for t in trails
        )

        try:
            statuses = self.cfg.describe_configuration_recorder_status()
            evidence["reliability"]["config_recorder_active"] = any(
                r.get('recording', False)
                for r in statuses['ConfigurationRecordersStatus']
            )
        except ClientError:
            evidence["reliability"]["config_recorder_active"] = False

        try:
            plans = self.backup.list_backup_plans()['BackupPlansList']
            evidence["reliability"]["backup_plans_exist"] = len(plans) > 0
        except ClientError:
            evidence["reliability"]["backup_plans_exist"] = False

        if allInstances:
            azs = {i['Placement']['AvailabilityZone'] for i in allInstances}
            evidence["reliability"]["multi_az_instances"] = len(azs) >= 2
        else:
            evidence["reliability"]["multi_az_instances"] = None  # N/A — no EC2 instances

        if rdsInstances:
            withBackup = sum(
                1 for i in rdsInstances if i.get('BackupRetentionPeriod', 0) > 0
            )
            evidence["reliability"]["rds_backup_enabled_ratio"] = withBackup / len(rdsInstances)
        else:
            evidence["reliability"]["rds_backup_enabled_ratio"] = 1.0

        if rdsInstances:
            multiAz = sum(1 for i in rdsInstances if i.get('MultiAZ'))
            evidence["reliability"]["rds_multi_az_ratio"] = multiAz / len(rdsInstances)
        else:
            evidence["reliability"]["rds_multi_az_ratio"] = 1.0

        # EKS cluster and node group health
        try:
            clusterNames          = self.eks.list_clusters().get('clusters', [])
            clusterFailureCount   = 0
            nodegroupFailureCount = 0
            outdatedClusterCount  = 0

            for name in clusterNames:
                cluster = self.eks.describe_cluster(name=name)['cluster']

                if cluster.get('status') not in ('ACTIVE', 'UPDATING'):
                    clusterFailureCount += 1

                if cluster.get('version', '') not in EKS_SUPPORTED_VERSIONS:
                    outdatedClusterCount += 1

                for ngName in self.eks.list_nodegroups(clusterName=name).get('nodegroups', []):
                    ng = self.eks.describe_nodegroup(
                        clusterName=name, nodegroupName=ngName
                    )['nodegroup']
                    if ng.get('status') in ('CREATE_FAILED', 'DELETE_FAILED', 'DEGRADED'):
                        nodegroupFailureCount += 1

            evidence["reliability"]["eks_cluster_failure_count"]   = clusterFailureCount
            evidence["reliability"]["eks_nodegroup_failure_count"] = nodegroupFailureCount
            evidence["operational_excellence"]["eks_outdated_cluster_count"] = outdatedClusterCount

        except ClientError:
            evidence["reliability"]["eks_cluster_failure_count"]             = 0
            evidence["reliability"]["eks_nodegroup_failure_count"]           = 0
            evidence["operational_excellence"]["eks_outdated_cluster_count"] = 0

        # ── Operational Excellence ────────────────────────────────────────────────

        try:
            alarms = self.cw.describe_alarms()['MetricAlarms']
            evidence["operational_excellence"]["cloudwatch_alarm_count"] = len(alarms)
        except ClientError:
            evidence["operational_excellence"]["cloudwatch_alarm_count"] = 0

        try:
            rules = self.cfg.describe_config_rules()['ConfigRules']
            evidence["operational_excellence"]["config_rule_count"] = len(rules)
        except ClientError:
            evidence["operational_excellence"]["config_rule_count"] = 0

        evidence["operational_excellence"]["trail_log_validation"] = any(
            t.get('LogFileValidationEnabled', False) for t in trails
        )

        try:
            info = self.acc.get_account_information()
            age  = (datetime.now(timezone.utc) - info['AccountCreatedDate']).days
            evidence["operational_excellence"]["account_age_days"] = age
        except ClientError:
            evidence["operational_excellence"]["account_age_days"] = 30

        # S3 server access logs are the only record of who read or deleted objects.
        # Without them there's nothing to investigate after a data exfiltration event.
        loggingEnabled = 0
        for b in buckets:
            try:
                resp = self.s3.get_bucket_logging(Bucket=b['Name'])
                if resp.get('LoggingEnabled'):
                    loggingEnabled += 1
            except ClientError:
                pass
        evidence["operational_excellence"]["s3_access_logging_ratio"] = (
            loggingEnabled / totalBuckets if totalBuckets else 1.0
        )

        # Without CloudTrail → CloudWatch there are no real-time alerts for API abuse
        evidence["operational_excellence"]["cloudtrail_cloudwatch_logs"] = any(
            t.get('CloudWatchLogsLogGroupArn') for t in trails
        )

        # Orphaned volumes and IPs indicate configuration drift
        try:
            idleVols = self.ec2.describe_volumes(
                Filters=[{'Name': 'status', 'Values': ['available']}]
            )['Volumes']
            evidence["operational_excellence"]["unattached_ebs_count"] = len(idleVols)
        except ClientError:
            evidence["operational_excellence"]["unattached_ebs_count"] = 0

        try:
            addrs = self.ec2.describe_addresses()['Addresses']
            evidence["operational_excellence"]["unused_elastic_ip_count"] = sum(
                1 for a in addrs if 'AssociationId' not in a
            )
        except ClientError:
            evidence["operational_excellence"]["unused_elastic_ip_count"] = 0

        try:
            noLifecycle = 0
            for b in buckets:
                try:
                    self.s3.get_bucket_lifecycle_configuration(Bucket=b['Name'])
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
                        noLifecycle += 1
            evidence["reliability"]["s3_buckets_missing_lifecycle"] = noLifecycle
        except ClientError:
            evidence["reliability"]["s3_buckets_missing_lifecycle"] = 0

        # Old-generation instances lack Nitro security features and modern hardware
        if allInstances:
            oldGenCount = sum(
                1 for i in allInstances
                if i['InstanceType'].split('.')[0] in OLD_GEN_FAMILIES
            )
            evidence["operational_excellence"]["old_gen_instance_ratio"] = (
                oldGenCount / len(allInstances)
            )
        else:
            evidence["operational_excellence"]["old_gen_instance_ratio"] = 0.0

        # Instances running for >1 year are likely lagging on OS patches
        if allInstances:
            staleThreshold = datetime.now(timezone.utc) - timedelta(days=365)
            staleCount = sum(
                1 for i in allInstances if i['LaunchTime'] < staleThreshold
            )
            evidence["operational_excellence"]["stale_instance_ratio"] = (
                staleCount / len(allInstances)
            )
        else:
            evidence["operational_excellence"]["stale_instance_ratio"] = 0.0

        # ── Performance Efficiency ────────────────────────────────────────────────

        try:
            asgs = self.autoscaling.describe_auto_scaling_groups()['AutoScalingGroups']
            # N/A if no instances — having 0 ASGs is only meaningful when EC2 is in use
            evidence["performance_efficiency"]["autoscaling_group_count"] = (
                len(asgs) if allInstances else None
            )
        except ClientError:
            evidence["performance_efficiency"]["autoscaling_group_count"] = None

        try:
            distList = self.cf.list_distributions()['DistributionList']
            cfCount  = len(distList.get('Items', []))
            # N/A if account has no instances or buckets to serve through CloudFront
            evidence["performance_efficiency"]["cloudfront_distribution_count"] = (
                cfCount if (allInstances or totalBuckets) else None
            )
        except ClientError:
            evidence["performance_efficiency"]["cloudfront_distribution_count"] = None

        if allInstances:
            families         = {i['InstanceType'].split('.')[0] for i in allInstances}
            gravitonFamilies = {'t4g', 'c7g', 'm7g', 'r7g', 'c6g', 'm6g', 'r6g'}
            evidence["performance_efficiency"]["graviton_instances_used"] = bool(
                families & gravitonFamilies
            )
        else:
            evidence["performance_efficiency"]["graviton_instances_used"] = None  # N/A

        return evidence
