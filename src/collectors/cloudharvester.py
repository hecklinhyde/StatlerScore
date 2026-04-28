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
        """
        Pass a boto3.Session to use specific credentials/region.
        Falls back to boto3's default credential chain if session is None.
        """
        self._session = session
        mk = session.client if session else boto3.client
        # Global services only — regional clients are created per-region in _collect_region
        self.s3  = mk('s3')
        self.iam = mk('iam')
        self.acc = mk('account')
        self.cf  = mk('cloudfront')

    def _client(self, service, region, timeout=None):
        cfg = BotocoreConfig(connect_timeout=timeout, read_timeout=timeout) if timeout else None
        kwargs = dict(region_name=region)
        if cfg:
            kwargs['config'] = cfg
        if self._session:
            return self._session.client(service, **kwargs)
        return boto3.client(service, **kwargs)

    def _regions(self):
        """Return all enabled regions for this account."""
        try:
            ec2 = self._client('ec2', 'us-east-1')
            resp = ec2.describe_regions(
                Filters=[{'Name': 'opt-in-status', 'Values': ['opt-in-not-required', 'opted-in']}]
            )
            return [r['RegionName'] for r in resp['Regions']]
        except Exception:
            return ['us-east-1']

    def _collect_region(self, region):
        """Collect all regional data for a single region. Never raises."""
        data = {}

        # EC2 instances
        try:
            ec2 = self._client('ec2', region)
            reservations = ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )['Reservations']
            data['instances'] = [i for r in reservations for i in r['Instances']]
        except Exception:
            data['instances'] = []

        # Security groups
        try:
            ec2 = self._client('ec2', region)
            data['security_groups'] = ec2.describe_security_groups()['SecurityGroups']
        except Exception:
            data['security_groups'] = []

        # VPCs and flow logs
        try:
            ec2 = self._client('ec2', region)
            data['vpcs'] = ec2.describe_vpcs()['Vpcs']
            data['flow_logs'] = ec2.describe_flow_logs()['FlowLogs']
        except Exception:
            data['vpcs'] = []
            data['flow_logs'] = []

        # EBS encryption default
        try:
            ec2 = self._client('ec2', region)
            data['ebs_encrypt_default'] = ec2.get_ebs_encryption_by_default()['EbsEncryptionByDefault']
        except Exception:
            data['ebs_encrypt_default'] = False

        # Unattached EBS volumes
        try:
            ec2 = self._client('ec2', region)
            data['ebs_unattached'] = len(ec2.describe_volumes(
                Filters=[{'Name': 'status', 'Values': ['available']}]
            )['Volumes'])
        except Exception:
            data['ebs_unattached'] = 0

        # Unused Elastic IPs
        try:
            ec2 = self._client('ec2', region)
            addrs = ec2.describe_addresses()['Addresses']
            data['elastic_ips_unused'] = sum(1 for a in addrs if 'AssociationId' not in a)
        except Exception:
            data['elastic_ips_unused'] = 0

        # Deprecated AMIs (based on instance AMI IDs in this region)
        try:
            ec2 = self._client('ec2', region)
            amiIds = list({i['ImageId'] for i in data['instances']})[:100]
            if amiIds:
                images = ec2.describe_images(ImageIds=amiIds)['Images']
                now = datetime.now(timezone.utc)
                deprecated = sum(
                    1 for img in images
                    if img.get('DeprecationTime') and
                    datetime.fromisoformat(img['DeprecationTime'].replace('Z', '+00:00')) < now
                )
                data['deprecated_ami_count'] = deprecated
                data['ami_total'] = len(amiIds)
            else:
                data['deprecated_ami_count'] = 0
                data['ami_total'] = 0
        except Exception:
            data['deprecated_ami_count'] = 0
            data['ami_total'] = 0

        # RDS instances
        try:
            rds = self._client('rds', region)
            data['rds_instances'] = rds.describe_db_instances()['DBInstances']
        except Exception:
            data['rds_instances'] = []

        # RDS public snapshots
        try:
            rds = self._client('rds', region)
            manualSnaps = rds.describe_db_snapshots(SnapshotType='manual')['DBSnapshots']
            publicSnaps = 0
            for snap in manualSnaps[:20]:
                attrs = rds.describe_db_snapshot_attributes(
                    DBSnapshotIdentifier=snap['DBSnapshotIdentifier']
                )['DBSnapshotAttributesResult']['DBSnapshotAttributes']
                if any(
                    a['AttributeName'] == 'restore' and 'all' in a['AttributeValues']
                    for a in attrs
                ):
                    publicSnaps += 1
            data['rds_public_snaps'] = publicSnaps
        except Exception:
            data['rds_public_snaps'] = 0

        # EKS clusters and node groups
        try:
            eks = self._client('eks', region)
            clusterNames = eks.list_clusters().get('clusters', [])
            eks_clusters = []
            for name in clusterNames:
                cluster = eks.describe_cluster(name=name)['cluster']
                nodegroups = []
                for ngName in eks.list_nodegroups(clusterName=name).get('nodegroups', []):
                    ng = eks.describe_nodegroup(clusterName=name, nodegroupName=ngName)['nodegroup']
                    nodegroups.append(ng)
                eks_clusters.append({'cluster': cluster, 'nodegroups': nodegroups})
            data['eks_clusters'] = eks_clusters
        except Exception:
            data['eks_clusters'] = []

        # GuardDuty
        try:
            gd = self._client('guardduty', region)
            detectors = gd.list_detectors()['DetectorIds']
            data['guardduty_enabled'] = len(detectors) > 0
        except Exception:
            data['guardduty_enabled'] = False

        # CloudWatch alarms
        try:
            cw = self._client('cloudwatch', region)
            data['cw_alarm_count'] = len(cw.describe_alarms()['MetricAlarms'])
        except Exception:
            data['cw_alarm_count'] = 0

        # Config recorder and rules (10 s timeout — Config APIs are slow)
        try:
            cfg = self._client('config', region, timeout=10)
            statuses = cfg.describe_configuration_recorder_status()
            data['config_recording'] = any(
                r.get('recording', False)
                for r in statuses['ConfigurationRecordersStatus']
            )
        except Exception:
            data['config_recording'] = False

        try:
            cfg = self._client('config', region, timeout=10)
            data['config_rules'] = len(cfg.describe_config_rules()['ConfigRules'])
        except Exception:
            data['config_rules'] = 0

        # CloudTrail (homed trails only — no shadow duplicates)
        try:
            ct = self._client('cloudtrail', region)
            data['trails'] = ct.describe_trails(includeShadowTrails=False)['trailList']
        except Exception:
            data['trails'] = []

        # Backup plans
        try:
            backup = self._client('backup', region)
            data['backup_plans'] = len(backup.list_backup_plans()['BackupPlansList'])
        except Exception:
            data['backup_plans'] = 0

        # Access Analyzer
        try:
            aa = self._client('accessanalyzer', region)
            analyzers = aa.list_analyzers()['analyzers']
            data['access_analyzer'] = any(a['status'] == 'ACTIVE' for a in analyzers)
        except Exception:
            data['access_analyzer'] = False

        # Security Hub
        try:
            sh = self._client('securityhub', region)
            sh.describe_hub()
            data['security_hub'] = True
        except ClientError as e:
            # InvalidAccessException means not enabled; other errors = treat as disabled
            data['security_hub'] = False
        except Exception:
            data['security_hub'] = False

        # Auto Scaling groups
        try:
            asg = self._client('autoscaling', region)
            data['asg_count'] = len(asg.describe_auto_scaling_groups()['AutoScalingGroups'])
        except Exception:
            data['asg_count'] = 0

        return region, data

    def collect(self):
        evidence = {
            "security, privacy, and compliance": {},
            "reliability":            {},
            "operational_excellence": {},
            "performance_efficiency": {},
        }

        regions = self._regions()
        print(f"  Scanning {len(regions)} regions in parallel...")
        regional = {}
        with ThreadPoolExecutor(max_workers=min(len(regions), 12)) as ex:
            futures = {ex.submit(self._collect_region, r): r for r in regions}
            for future in as_completed(futures):
                r, data = future.result()
                regional[r] = data

        allInstances      = [i for r in regional.values() for i in r['instances']]
        rdsInstances      = [i for r in regional.values() for i in r['rds_instances']]
        allSecurityGroups = [sg for r in regional.values() for sg in r['security_groups']]
        allVpcs           = [v for r in regional.values() for v in r['vpcs']]
        allFlowLogs       = [fl for r in regional.values() for fl in r['flow_logs']]

        # Union trails by ARN to avoid counting multi-region trail duplicates
        trailsByArn = {}
        for r in regional.values():
            for t in r['trails']:
                trailsByArn[t['TrailARN']] = t
        allTrails = list(trailsByArn.values())

    def _listRunningInstances(self):
        def fetch():
            reservations = self.ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )['Reservations']
            return [i for r in reservations for i in r['Instances']]
        return _safeCall(fetch, [])
        # Boolean checks that must be true in ALL regions
        guardduty_enabled     = all(r['guardduty_enabled']  for r in regional.values())
        security_hub_enabled  = all(r['security_hub']       for r in regional.values())
        ebs_encryption_default = all(r['ebs_encrypt_default'] for r in regional.values())
        config_recorder_active = all(r['config_recording']  for r in regional.values())

        # Boolean checks where ANY region suffices
        access_analyzer_active = any(r['access_analyzer'] for r in regional.values())
        backup_plans_exist     = any(r['backup_plans'] > 0 for r in regional.values())

        # Summable counts
        cw_alarm_count      = sum(r['cw_alarm_count']      for r in regional.values())
        config_rule_count   = sum(r['config_rules']        for r in regional.values())
        ebs_unattached      = sum(r['ebs_unattached']      for r in regional.values())
        elastic_ips_unused  = sum(r['elastic_ips_unused']  for r in regional.values())
        asg_count           = sum(r['asg_count']           for r in regional.values())
        rds_public_snaps    = sum(r['rds_public_snaps']    for r in regional.values())

        # AMI deprecation — sum per-region counts then compute ratio
        total_deprecated_ami = sum(r['deprecated_ami_count'] for r in regional.values())
        total_ami            = sum(r['ami_total']             for r in regional.values())

        # EKS — collect all cluster records across regions
        all_eks_clusters = [c for r in regional.values() for c in r['eks_clusters']]

        buckets = self.s3.list_buckets()['Buckets']
        totalBuckets = len(buckets)

        summary = self.iam.get_account_summary()
        evidence["security, privacy, and compliance"]["root_mfa_enabled"] = (
            summary['SummaryMap'].get('AccountMFAEnabled', 0) == 1
        )

        try:
            self.iam.get_account_password_policy()
            evidence["security, privacy, and compliance"]["password_policy_set"] = True
        except self.iam.exceptions.NoSuchEntityException:
            evidence["security, privacy, and compliance"]["password_policy_set"] = False

        # Ratio of buckets that aren't fully public-access-blocked
        publicCount = 0
        for b in buckets:
            try:
                blk = self.s3.get_public_access_block(Bucket=b['Name'])
                if not all(blk['PublicAccessBlockConfiguration'].values()):
                    publicCount += 1
            except ClientError:
                publicCount += 1  # no block config = treat as public
        evidence["security, privacy, and compliance"]["s3_public_bucket_ratio"] = (
            publicCount / totalBuckets if totalBuckets else 0.0
        )

        evidence["security, privacy, and compliance"]["guardduty_enabled"] = guardduty_enabled

        # Ratio of access keys older than 90 days (lower = better)
        try:
            users  = self.iam.list_users()['Users']
            cutoff = datetime.now(timezone.utc) - timedelta(days=360)
            totalKeys, staleKeys = 0, 0
            for user in users:
                keys = self.iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
                for key in keys:
                    totalKeys += 1
                    if key['CreateDate'] < cutoff:
                        staleKeys += 1
            evidence["security, privacy, and compliance"]["stale_access_key_ratio"] = (
                staleKeys / totalKeys if totalKeys else 0.0
            )
        except ClientError:
            evidence["security, privacy, and compliance"]["stale_access_key_ratio"] = 0.0

        try:
            mfaDevices   = self.iam.list_virtual_mfa_devices()['VirtualMFADevices']
            usersWithMfa = sum(1 for d in mfaDevices if 'User' in d)
            totalUsers   = len(self.iam.list_users()['Users'])
            evidence["security, privacy, and compliance"]["iam_user_mfa_ratio"] = (
                usersWithMfa / totalUsers if totalUsers else 1.0
            )
        except ClientError:
            evidence["security, privacy, and compliance"]["iam_user_mfa_ratio"] = 0.0

        # IMDSv2 — every instance allowing IMDSv1 is a potential SSRF-to-credential-theft path
        if allInstances:
            imdsv2Count = sum(
                1 for i in allInstances
                if i.get('MetadataOptions', {}).get('HttpTokens') == 'required'
            )
            evidence["security, privacy, and compliance"]["imdsv2_enforced_ratio"] = imdsv2Count / len(allInstances)
        else:
            evidence["security, privacy, and compliance"]["imdsv2_enforced_ratio"] = 1.0

        #  https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/security-group-open-to-internet/
        openSgCount = 0
        for sg in allSecurityGroups:
            for perm in sg.get('IpPermissions', []):
                fromPort = perm.get('FromPort') or 0
                toPort   = perm.get('ToPort')   or 65535
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
        evidence["security, privacy, and compliance"]["open_security_group_count"] = openSgCount

        if rdsInstances:
            publicRds = sum(1 for i in rdsInstances if i.get('PubliclyAccessible'))
            evidence["security, privacy, and compliance"]["rds_public_instance_ratio"] = publicRds / len(rdsInstances)
        else:
            evidence["security, privacy, and compliance"]["rds_public_instance_ratio"] = 0.0

        evidence["security, privacy, and compliance"]["ebs_encryption_by_default"] = ebs_encryption_default

        if allVpcs:
            loggedIds = {fl['ResourceId'] for fl in allFlowLogs}
            vpcIds    = {v['VpcId'] for v in allVpcs}
            evidence["security, privacy, and compliance"]["vpc_flow_logs_ratio"] = (
                len(vpcIds & loggedIds) / len(vpcIds)
            )
        else:
            evidence["security, privacy, and compliance"]["vpc_flow_logs_ratio"] = 1.0

        evidence["security, privacy, and compliance"]["access_analyzer_active"] = access_analyzer_active

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
            evidence["security, privacy, and compliance"]["iam_wildcard_admin_count"] = wildcardCount
        except ClientError:
            evidence["security, privacy, and compliance"]["iam_wildcard_admin_count"] = 0

        # Versioning is the primary ransomware defence for S3
        try:
            versioned = sum(
                1 for b in buckets
                if self.s3.get_bucket_versioning(Bucket=b['Name']).get('Status') == 'Enabled'
            )
            evidence["security, privacy, and compliance"]["s3_versioning_ratio"] = (
                versioned / totalBuckets if totalBuckets else 1.0
            )
        except ClientError:
            evidence["security, privacy, and compliance"]["s3_versioning_ratio"] = 0.0

        #  https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html
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
        evidence["security, privacy, and compliance"]["s3_tls_enforced_ratio"] = (
            tlsEnforced / totalBuckets if totalBuckets else 1.0
        )

        # https://aws.amazon.com/blogs/security/iam-policies-and-bucket-policies-and-acls-oh-my-controlling-access-to-s3-resources/
        aclDisabled = 0
        for b in buckets:
            try:
                controls = self.s3.get_bucket_ownership_controls(Bucket=b['Name'])
                rules    = controls.get('OwnershipControls', {}).get('Rules', [])
                if any(r.get('ObjectOwnership') == 'BucketOwnerEnforced' for r in rules):
                    aclDisabled += 1
            except ClientError:
                pass
        evidence["security, privacy, and compliance"]["s3_acl_disabled_ratio"] = (
            aclDisabled / totalBuckets if totalBuckets else 1.0
        )

        evidence["security, privacy, and compliance"]["security_hub_enabled"] = security_hub_enabled

        # https://www.elastic.co/guide/en/security/8.19/aws-ec2-deprecated-ami-discovery.html
        if total_ami > 0:
            evidence["security, privacy, and compliance"]["deprecated_ami_ratio"] = total_deprecated_ami / total_ami
        else:
            evidence["security, privacy, and compliance"]["deprecated_ami_ratio"] = 0.0
        # https://docs.aws.amazon.com/config/latest/developerguide/rds-snapshots-public-prohibited.html
        evidence["security, privacy, and compliance"]["rds_public_snapshot_count"] = rds_public_snaps

        # --- reliability ---

        evidence["reliability"]["cloudtrail_enabled"]     = len(allTrails) > 0
        evidence["reliability"]["cloudtrail_multiregion"] = any(
            t.get('IsMultiRegionTrail', False) for t in allTrails
        )

        evidence["reliability"]["config_recorder_active"] = config_recorder_active

        evidence["reliability"]["backup_plans_exist"] = backup_plans_exist

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

        if rdsInstances:
            piEnabled = sum(1 for i in rdsInstances if i.get('PerformanceInsightsEnabled'))
            evidence["performance_efficiency"]["rds_performance_insights_ratio"] = piEnabled / len(rdsInstances)
        else:
            evidence["performance_efficiency"]["rds_performance_insights_ratio"] = None

        # EKS cluster and node group health
        clusterFailureCount   = 0
        nodegroupFailureCount = 0
        outdatedClusterCount  = 0
        for entry in all_eks_clusters:
            cluster = entry['cluster']
            if cluster.get('status') not in ('ACTIVE', 'UPDATING'):
                clusterFailureCount += 1
            if cluster.get('version', '') not in EKS_SUPPORTED_VERSIONS:
                outdatedClusterCount += 1
            for ng in entry['nodegroups']:
                if ng.get('status') in ('CREATE_FAILED', 'DELETE_FAILED', 'DEGRADED'):
                    nodegroupFailureCount += 1

        evidence["reliability"]["eks_cluster_failure_count"]             = clusterFailureCount
        evidence["reliability"]["eks_nodegroup_failure_count"]           = nodegroupFailureCount
        evidence["operational_excellence"]["eks_outdated_cluster_count"] = outdatedClusterCount

        # --- operational excellence ---

        evidence["operational_excellence"]["cloudwatch_alarm_count"] = cw_alarm_count

        evidence["operational_excellence"]["config_rule_count"] = config_rule_count

        evidence["operational_excellence"]["trail_log_validation"] = any(
            t.get('LogFileValidationEnabled', False) for t in allTrails
        )

        try:
            info = self.acc.get_account_information()
            age  = (datetime.now(timezone.utc) - info['AccountCreatedDate']).days
            evidence["operational_excellence"]["account_age_days"] = age
        except ClientError:
            evidence["operational_excellence"]["account_age_days"] = 30

        # S3 server access logs
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

        evidence["operational_excellence"]["cloudtrail_cloudwatch_logs"] = any(
            t.get('CloudWatchLogsLogGroupArn') for t in allTrails
        )

        evidence["operational_excellence"]["unattached_ebs_count"]   = ebs_unattached
        evidence["operational_excellence"]["unused_elastic_ip_count"] = elastic_ips_unused

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

        # --- performance ---

        evidence["performance_efficiency"]["autoscaling_group_count"] = (
            asg_count if allInstances else None
        )

        try:
            distList = self.cf.list_distributions()['DistributionList']
            cfCount  = len(distList.get('Items', []))
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
