import boto3
import json
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta

SENSITIVE_PORTS = {20, 21, 22, 23, 25, 3389, 1433, 2375, 3306, 5432, 27017, 6379, 9200}

# https://docs.aws.amazon.com/ec2/latest/instancetypes/instance-types.html#previous-gen-instances
OLD_GEN_FAMILIES = {
    't1', 't2',
    'm1', 'm2', 'm3', 'm4',
    'c1', 'c3', 'c4',
    'r3', 'r4',
    'i2', 'd2', 'hs1', 'g2',
}

GRAVITON_FAMILIES = {'t4g', 'c7g', 'm7g', 'r7g', 'c6g', 'm6g', 'r6g'}

# https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html
EKS_SUPPORTED_VERSIONS = {'1.29', '1.30', '1.31', '1.32'}

# define limits now so to avoid long lasting API calls
POLICY_SCAN_LIMIT = 50
AMI_LOOKUP_LIMIT = 100
RDS_SNAPSHOT_SCAN_LIMIT = 20

# Thresholds that mark a resource as "stale" for hygiene checks.
STALE_KEY_DAYS = 90
STALE_INSTANCE_DAYS = 365

# Safe calls to handle errors
def _safeCall(fn, default):
    try:
        return fn()
    except ClientError:
        return default

def _safeRatio(numerator, denominator, defaultWhenEmpty):
    return numerator / denominator if denominator else defaultWhenEmpty
 

class CloudHarvester:
    def __init__(self, session=None):
        mk = session.client if session else boto3.client
        self.s3             = mk('s3')
        self.iam            = mk('iam')
        self.ct             = mk('cloudtrail')
        self.account        = mk('account')
        self.cloudwatch     = mk('cloudwatch')
        self.config         = mk('config')
        self.ec2            = mk('ec2')
        self.guardduty      = mk('guardduty')
        self.backup         = mk('backup')
        self.autoscaling    = mk('autoscaling')
        self.cloudfront     = mk('cloudfront')
        self.rds            = mk('rds')
        self.accessanalyzer = mk('accessanalyzer')
        self.securityhub    = mk('securityhub')
        self.eks            = mk('eks')

    def collect(self):
        # Fetch shared resources up front to avoid redundant API calls
        trails = _safeCall(lambda: self.ct.describe_trails()['trailList'], [])
        buckets = _safeCall(lambda: self.s3.list_buckets()['Buckets'], [])
        ec2Instances = self._listRunningInstances()
        rdsInstances = _safeCall(lambda: self.rds.describe_db_instances()['DBInstances'], [])
 
        evidence = {
            "security_privacy_compliance": self._collectSecurity(buckets, ec2Instances, rdsInstances),
            "reliability":self._collectReliability(trails, buckets, ec2Instances, rdsInstances),
            "operational_excellence": self._collectOperationalExcellence(trails, buckets, ec2Instances),
            "performance_efficiency": self._collectPerformanceEfficiency(buckets, ec2Instances),
        }
        return evidence

    def _listRunningInstances(self):
        def fetch():
            reservations = self.ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )['Reservations']
            return [i for r in reservations for i in r['Instances']]
        return _safeCall(fetch, [])
    
# security privacy compliance──────────────────────────────────────────────

    def _collectSecurity(self, buckets, ec2Instances, rdsInstances):
        sec = {}
        totalBuckets = len(buckets)
 
        summary = self.iam.get_account_summary()
        sec["root_mfa_enabled"] = summary['SummaryMap'].get('AccountMFAEnabled', 0) == 1
 
        try:
            self.iam.get_account_password_policy()
            sec["password_policy_set"] = True
        except self.iam.exceptions.NoSuchEntityException:
            sec["password_policy_set"] = False
 
        # Ratio of buckets that aren't fully public-access-blocked
        publicCount = 0
        for b in buckets:
            try:
                blk = self.s3.get_public_access_block(Bucket=b['Name'])
                if not all(blk['PublicAccessBlockConfiguration'].values()):
                    publicCount += 1
            except ClientError:
                publicCount += 1  # no block config = treat as public
        sec["s3_public_bucket_ratio"] = _safeRatio(publicCount, totalBuckets, 0.0)
 
        sec["guardduty_enabled"] = _safeCall(
            lambda: len(self.gd.list_detectors()['DetectorIds']) > 0, False
        )
 
        # Ratio of access keys older than 90 days (lower = better)
        try:
            users  = self.iam.list_users()['Users']
            cutoff = datetime.now(timezone.utc) - timedelta(days=STALE_KEY_DAYS)
            totalKeys, staleKeys = 0, 0
            for user in users:
                keys = self.iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
                for key in keys:
                    totalKeys += 1
                    if key['CreateDate'] < cutoff:
                        staleKeys += 1
            sec["stale_access_key_ratio"] = _safeRatio(staleKeys, totalKeys, 0.0)
        except ClientError:
            sec["stale_access_key_ratio"] = 0.0
 
        try:
            mfaDevices   = self.iam.list_virtual_mfa_devices()['VirtualMFADevices']
            usersWithMfa = sum(1 for d in mfaDevices if 'User' in d)
            totalUsers   = len(self.iam.list_users()['Users'])
            sec["iam_user_mfa_ratio"] = _safeRatio(usersWithMfa, totalUsers, 1.0)
        except ClientError:
            sec["iam_user_mfa_ratio"] = 0.0
 
        # https://aws.amazon.com/blogs/security/get-the-full-benefits-of-imdsv2-and-disable-imdsv1-across-your-aws-infrastructure/
        if ec2Instances:
            imdsv2Count = sum(
                1 for i in ec2Instances
                if i.get('MetadataOptions', {}).get('HttpTokens') == 'required'
            )
            sec["imdsv2_enforced_ratio"] = imdsv2Count / len(ec2Instances)
        else:
            sec["imdsv2_enforced_ratio"] = 1.0
 
        # Security groups with sensitive ports open to 0.0.0.0/0
        try:
            sgs = self.ec2.describe_security_groups()['SecurityGroups']
            sec["open_security_group_count"] = sum(
                1 for sg in sgs if self._sgExposesSensitivePort(sg)
            )
        except ClientError:
            sec["open_security_group_count"] = 0
 
        if rdsInstances:
            publicRds = sum(1 for i in rdsInstances if i.get('PubliclyAccessible'))
            sec["rds_public_instance_ratio"] = publicRds / len(rdsInstances)
        else:
            sec["rds_public_instance_ratio"] = 0.0
 
        sec["ebs_encryption_by_default"] = _safeCall(
            lambda: self.ec2.get_ebs_encryption_by_default()['EbsEncryptionByDefault'],
            False,
        )
 
        try:
            vpcs      = self.ec2.describe_vpcs()['Vpcs']
            flowLogs  = self.ec2.describe_flow_logs()['FlowLogs']
            loggedIds = {fl['ResourceId'] for fl in flowLogs}
            vpcIds    = {v['VpcId'] for v in vpcs}
            sec["vpc_flow_logs_ratio"] = _safeRatio(len(vpcIds & loggedIds), len(vpcIds), 1.0)
        except ClientError:
            sec["vpc_flow_logs_ratio"] = 0.0
 
        # https://aws.amazon.com/iam/access-analyzer/
        try:
            analyzers = self.accessanalyzer.list_analyzers()['analyzers']
            sec["access_analyzer_active"] = any(a['status'] == 'ACTIVE' for a in analyzers)
        except ClientError:
            sec["access_analyzer_active"] = False
 
        # https://docs.aws.amazon.com/kms/latest/developerguide/iam-policies-best-practices.html
        try:
            policies      = self.iam.list_policies(Scope='Local', OnlyAttached=True)['Policies']
            wildcardCount = 0
            for policy in policies[:POLICY_SCAN_LIMIT]:
                doc = self.iam.get_policy_version(
                    PolicyArn=policy['Arn'],
                    VersionId=policy['DefaultVersionId']
                )['PolicyVersion']['Document']
                if self._policyHasWildcardAdmin(doc):
                    wildcardCount += 1
            sec["iam_wildcard_admin_count"] = wildcardCount
        except ClientError:
            sec["iam_wildcard_admin_count"] = 0
 
        # https://rhinosecuritylabs.com/aws/s3-ransomware-part-2-prevention-and-defense/
        try:
            versioned = sum(
                1 for b in buckets
                if self.s3.get_bucket_versioning(Bucket=b['Name']).get('Status') == 'Enabled'
            )
            sec["s3_versioning_ratio"] = _safeRatio(versioned, totalBuckets, 1.0)
        except ClientError:
            sec["s3_versioning_ratio"] = 0.0
 
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html
        # The fix is a Deny statement conditioned on aws:SecureTransport = false.
        tlsEnforced = 0
        for b in buckets:
            try:
                policy = json.loads(self.s3.get_bucket_policy(Bucket=b['Name'])['Policy'])
                if self._policyDeniesInsecureTransport(policy):
                    tlsEnforced += 1
            except ClientError:
                pass  # no policy = HTTP not denied
        sec["s3_tls_enforced_ratio"] = _safeRatio(tlsEnforced, totalBuckets, 1.0)
 
        # https://aws.amazon.com/blogs/security/iam-policies-and-bucket-policies-and-acls-oh-my-controlling-access-to-s3-resources/
        aclDisabled = 0
        for b in buckets:
            try:
                controls = self.s3.get_bucket_ownership_controls(Bucket=b['Name'])
                rules    = controls.get('OwnershipControls', {}).get('Rules', [])
                if any(r.get('ObjectOwnership') == 'BucketOwnerEnforced' for r in rules):
                    aclDisabled += 1
            except ClientError:
                pass  # no ownership controls set = ACLs potentially active
        sec["s3_acl_disabled_ratio"] = _safeRatio(aclDisabled, totalBuckets, 1.0)
 
        # Security Hub aggregates findings from GuardDuty, Inspector, Macie, etc.
        try:
            self.securityhub.describe_hub()
            sec["security_hub_enabled"] = True
        except ClientError:
            sec["security_hub_enabled"] = False
 
        # https://www.elastic.co/guide/en/security/8.19/aws-ec2-deprecated-ami-discovery.html
        try:
            amiIds = list({i['ImageId'] for i in ec2Instances})[:AMI_LOOKUP_LIMIT]
            if amiIds:
                images          = self.ec2.describe_images(ImageIds=amiIds)['Images']
                now             = datetime.now(timezone.utc)
                deprecatedCount = sum(1 for img in images if self._amiDeprecated(img, now))
                sec["deprecated_ami_ratio"] = deprecatedCount / len(amiIds)
            else:
                sec["deprecated_ami_ratio"] = 0.0
        except ClientError:
            sec["deprecated_ami_ratio"] = 0.0
 
        # https://docs.aws.amazon.com/config/latest/developerguide/rds-snapshots-public-prohibited.html
        try:
            manualSnaps = self.rds.describe_db_snapshots(SnapshotType='manual')['DBSnapshots']
            publicSnaps = 0
            for snap in manualSnaps[:RDS_SNAPSHOT_SCAN_LIMIT]:
                attrs = self.rds.describe_db_snapshot_attributes(
                    DBSnapshotIdentifier=snap['DBSnapshotIdentifier']
                )['DBSnapshotAttributesResult']['DBSnapshotAttributes']
                if any(
                    a['AttributeName'] == 'restore' and 'all' in a['AttributeValues']
                    for a in attrs
                ):
                    publicSnaps += 1
            sec["rds_public_snapshot_count"] = publicSnaps
        except ClientError:
            sec["rds_public_snapshot_count"] = 0
 
        return sec
    
    # https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/security-group-open-to-internet/
    @staticmethod
    def _sgExposesSensitivePort(sg):
        for perm in sg.get('IpPermissions', []):
            fromPort = perm.get('FromPort', 0)
            toPort   = perm.get('ToPort', 65535)
            hitsSensitive = any(p in range(fromPort, toPort + 1) for p in SENSITIVE_PORTS)
            if not hitsSensitive:
                continue
            openToWorld = (
                any(r['CidrIp']   == '0.0.0.0/0' for r in perm.get('IpRanges',   [])) or
                any(r['CidrIpv6'] == '::/0'       for r in perm.get('Ipv6Ranges', []))
            )
            if openToWorld:
                return True
        return False
    
    # https://docs.aws.amazon.com/kms/latest/developerguide/iam-policies-best-practices.html
    @staticmethod
    def _policyHasWildcardAdmin(doc):
        for stmt in doc.get('Statement', []):
            action   = stmt.get('Action',   '')
            resource = stmt.get('Resource', '')
            if (stmt.get('Effect') == 'Allow' and
                    action   in ('*', ['*']) and
                    resource in ('*', ['*'])):
                return True
        return False

    # https://aws.amazon.com/blogs/security/how-to-use-bucket-policies-and-apply-defense-in-depth-to-help-secure-your-amazon-s3-data/
    @staticmethod
    def _policyDeniesInsecureTransport(policy):
        for stmt in policy.get('Statement', []):
            condition = stmt.get('Condition', {}).get('Bool', {})
            if (stmt.get('Effect') == 'Deny' and
                    condition.get('aws:SecureTransport') in ('false', False)):
                return True
        return False

    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ami-deprecate.html
    @staticmethod
    def _amiDeprecated(img, now):
        dep = img.get('DeprecationTime')
        if not dep:
            return False
        return datetime.fromisoformat(dep.replace('Z', '+00:00')) < now

#Reliability ──────────────────────────────────────────────────────────
    def _collectReliability(self, trails, buckets, ec2Instances, rdsInstances):
        rel = {}
 
        rel["cloudtrail_enabled"]     = len(trails) > 0
        rel["cloudtrail_multiregion"] = any(t.get('IsMultiRegionTrail', False) for t in trails)
 
        try:
            statuses = self.cfg.describe_configuration_recorder_status()
            rel["config_recorder_active"] = any(
                r.get('recording', False)
                for r in statuses['ConfigurationRecordersStatus']
            )
        except ClientError:
            rel["config_recorder_active"] = False
 
        rel["backup_plans_exist"] = _safeCall(
            lambda: len(self.backup.list_backup_plans()['BackupPlansList']) > 0, False
        )
 
        if ec2Instances:
            azs = {i['Placement']['AvailabilityZone'] for i in ec2Instances}
            rel["multi_az_instances"] = len(azs) >= 2
        else:
            rel["multi_az_instances"] = None  # N/A — no EC2 instances
 
        if rdsInstances:
            withBackup = sum(1 for i in rdsInstances if i.get('BackupRetentionPeriod', 0) > 0)
            rel["rds_backup_enabled_ratio"] = withBackup / len(rdsInstances)
        else:
            rel["rds_backup_enabled_ratio"] = 1.0
 
        if rdsInstances:
            multiAz = sum(1 for i in rdsInstances if i.get('MultiAZ'))
            rel["rds_multi_az_ratio"] = multiAz / len(rdsInstances)
        else:
            rel["rds_multi_az_ratio"] = 1.0
 
        noLifecycle = 0
        for b in buckets:
            try:
                self.s3.get_bucket_lifecycle_configuration(Bucket=b['Name'])
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
                    noLifecycle += 1
        rel["s3_buckets_missing_lifecycle"] = noLifecycle
 
        # eks_cluster_failure_count and eks_nodegroup_failure_count are set by collect()
        return rel
    
# Operational Excellence ───────────────────────────────────────────────
    def _collectOperationalExcellence(self, trails, buckets, ec2Instances):
        ops = {}
 
        ops["cloudwatch_alarm_count"] = _safeCall(
            lambda: len(self.cw.describe_alarms()['MetricAlarms']), 0
        )
 
        ops["config_rule_count"] = _safeCall(
            lambda: len(self.cfg.describe_config_rules()['ConfigRules']), 0
        )
 
        ops["trail_log_validation"] = any(
            t.get('LogFileValidationEnabled', False) for t in trails
        )
 
        try:
            info = self.acc.get_account_information()
            ops["account_age_days"] = (datetime.now(timezone.utc) - info['AccountCreatedDate']).days
        except ClientError:
            ops["account_age_days"] = 30
 
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/logging-with-S3.html
        loggingEnabled = 0
        for b in buckets:
            try:
                resp = self.s3.get_bucket_logging(Bucket=b['Name'])
                if resp.get('LoggingEnabled'):
                    loggingEnabled += 1
            except ClientError:
                pass
        ops["s3_access_logging_ratio"] = _safeRatio(loggingEnabled, len(buckets), 1.0)

        # Check cloudtrail
        ops["cloudtrail_cloudwatch_logs"] = any(
            t.get('CloudWatchLogsLogGroupArn') for t in trails
        )

        # https://docs.aws.amazon.com/prescriptive-guidance/latest/optimize-costs-microsoft-workloads/ebs-delete-ebs-volumes.html
        try:
            idleVols = self.ec2.describe_volumes(
                Filters=[{'Name': 'status', 'Values': ['available']}]
            )['Volumes']
            ops["unattached_ebs_count"] = len(idleVols)
        except ClientError:
            ops["unattached_ebs_count"] = 0
 
        try:
            addrs = self.ec2.describe_addresses()['Addresses']
            ops["unused_elastic_ip_count"] = sum(1 for a in addrs if 'AssociationId' not in a)
        except ClientError:
            ops["unused_elastic_ip_count"] = 0

        # Old-generation instances bad practices
        if ec2Instances:
            oldGenCount = sum(
                1 for i in ec2Instances
                if i['InstanceType'].split('.')[0] in OLD_GEN_FAMILIES
            )
            ops["old_gen_instance_ratio"] = oldGenCount / len(ec2Instances)
        else:
            ops["old_gen_instance_ratio"] = 0.0
        # eks_outdated_cluster_count is set by collect()
        return ops

# Performance Efficiency ───────────────────────────────────────────────
    def _collectPerformanceEfficiency(self, buckets, ec2Instances):
        perf = {}
        if ec2Instances:
            perf["autoscaling_group_count"] = _safeCall(
                lambda: len(self.autoscaling.describe_auto_scaling_groups()['AutoScalingGroups']),
                None,
            )
        else:
            perf["autoscaling_group_count"] = None
 
        if ec2Instances or buckets:
            perf["cloudfront_distribution_count"] = _safeCall(
                lambda: len(self.cf.list_distributions()['DistributionList'].get('Items', [])),
                None,
            )
        else:
            perf["cloudfront_distribution_count"] = None

        if ec2Instances:
            families = {i['InstanceType'].split('.')[0] for i in ec2Instances}
            perf["graviton_instances_used"] = bool(families & GRAVITON_FAMILIES)
        else:
            perf["graviton_instances_used"] = None  # N/A
 
        return perf

# EKS (cross-pillar) ───────────────────────────────────────────────────

    def _scanEksClusters(self):
        """Walk EKS clusters once; return counts that feed reliability + ops."""
        try:
            clusterNames = self.eks.list_clusters().get('clusters', [])
            clusterFailureCount = 0
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
 
            return {
                "clusterFailureCount":   clusterFailureCount,
                "nodegroupFailureCount": nodegroupFailureCount,
                "outdatedClusterCount":  outdatedClusterCount,
            }
        except ClientError:
            return {
                "clusterFailureCount": 0,
                "nodegroupFailureCount": 0,
                "outdatedClusterCount": 0,
            }