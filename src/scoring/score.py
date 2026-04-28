import math


# service -> fields that score 0 when absent; set to None (N/A) when user excludes the service
_SERVICE_SIGNALS = {
    "EC2": {
        "security, privacy, and compliance": {
            "imdsv2_enforced_ratio", "ebs_encryption_by_default",
            "deprecated_ami_ratio", "open_security_group_count",
        },
        "reliability": {"multi_az_instances"},
        "operational_excellence": {
            "unattached_ebs_count", "unused_elastic_ip_count",
            "old_gen_instance_ratio", "stale_instance_ratio",
        },
        "performance_efficiency": {"autoscaling_group_count", "graviton_instances_used"},
    },
    "RDS": {
        "security, privacy, and compliance": {"rds_public_instance_ratio", "rds_public_snapshot_count"},
        "reliability": {"rds_backup_enabled_ratio", "rds_multi_az_ratio"},
        "performance_efficiency": {"rds_performance_insights_ratio"},
    },
    "S3": {
        "security, privacy, and compliance": {
            "s3_public_bucket_ratio", "s3_versioning_ratio",
            "s3_tls_enforced_ratio", "s3_acl_disabled_ratio",
        },
        "reliability": {"s3_buckets_missing_lifecycle"},
        "operational_excellence": {"s3_access_logging_ratio"},
    },
    "EKS": {
        "reliability": {"eks_cluster_failure_count", "eks_nodegroup_failure_count"},
        "operational_excellence": {"eks_outdated_cluster_count"},
    },
    "CloudTrail": {
        "reliability": {"cloudtrail_enabled", "cloudtrail_multiregion"},
        "operational_excellence": {"trail_log_validation", "cloudtrail_cloudwatch_logs"},
    },
    "Config": {
        "reliability": {"config_recorder_active"},
        "operational_excellence": {"config_rule_count"},
    },
    "CloudFront":     {"performance_efficiency": {"cloudfront_distribution_count"}},
    "GuardDuty":      {"security, privacy, and compliance": {"guardduty_enabled"}},
    "SecurityHub":    {"security, privacy, and compliance": {"security_hub_enabled"}},
    "CloudWatch":     {"operational_excellence": {"cloudwatch_alarm_count"}},
    "Backup":         {"reliability": {"backup_plans_exist"}},
    "AccessAnalyzer": {"security, privacy, and compliance": {"access_analyzer_active"}},
    "VPCFlowLogs":    {"security, privacy, and compliance": {"vpc_flow_logs_ratio"}},
}

ALL_SERVICES = {
    "EC2":            "instances, EBS encryption, IMDSv2, Auto Scaling, Graviton",
    "RDS":            "databases, automated backups, Multi-AZ",
    "S3":             "buckets, versioning, TLS enforcement, access logging",
    "EKS":            "Kubernetes clusters and node groups",
    "CloudTrail":     "API activity logging, multi-region, log validation",
    "Config":         "configuration recorder and compliance rules",
    "CloudFront":     "CDN distributions",
    "GuardDuty":      "threat detection",
    "SecurityHub":    "security standards and findings aggregation",
    "CloudWatch":     "alarms and metrics",
    "Backup":         "backup plans and vaults",
    "AccessAnalyzer": "IAM Access Analyzer",
    "VPCFlowLogs":    "VPC traffic flow logging",
}


def _applyServiceFilter(data, pillar, active):
    # null out fields for any service the user said they don't have
    if active is None:
        return data
    result = dict(data)
    for svc, pillars in _SERVICE_SIGNALS.items():
        if svc not in active:
            for field in pillars.get(pillar, set()):
                result[field] = None
    return result


def flag(value) -> float:
    if value is None: return None
    return 1.0 if value else 0.0

def invert(ratio: float) -> float:
    if ratio is None: return None
    return 1.0 - float(ratio)

def ratio(value: float) -> float:
    if value is None: return None
    return float(value)

def capped(count: int, ceiling: int) -> float:
    if count is None: return None
    return min(1.0, count / ceiling)

def penalty(count: int, perUnit: float) -> float:
    if count is None: return None
    return max(0.0, 1.0 - count * perUnit)

def logAge(days: int, cap: int = 730) -> float:
    if days is None: return None
    return min(1.0, math.log(max(days, 1)) / math.log(cap))

def na(value, fn):
    """Apply fn to value; return None if value is None (service not in use)."""
    return None if value is None else fn(value)

def avg(signals: list[tuple[str, float]]):
    applicable = [(n, v) for n, v in signals if v is not None]
    if not applicable:
        return None  # pillar is N/A for this account — exclude from scoring
    return sum(v for _, v in applicable) / len(applicable)


# Each pillar function returns (score 0-1, [(check_name, signal_value), ...])
# 1.0 = best posture, 0.0 = worst

def scoreSecurity(sec: dict) -> tuple[float, list]:
    signals = [
        # identity & access
        ("Root account MFA",              flag(sec.get("root_mfa_enabled"))),
        ("IAM password policy",           flag(sec.get("password_policy_set"))),
        ("IAM user MFA coverage",         ratio(sec.get("iam_user_mfa_ratio", 0.0))),
        ("Wildcard admin IAM policies",   penalty(sec.get("iam_wildcard_admin_count", 0), 0.25)),
        # credentials
        ("Access key rotation",           invert(sec.get("stale_access_key_ratio", 0.0))),
        ("IMDSv2 enforcement on EC2",     ratio(sec.get("imdsv2_enforced_ratio", 0.0))),
        # data exposure
        ("S3 public bucket exposure",     invert(sec.get("s3_public_bucket_ratio", 0.0))),
        ("S3 versioning enabled",         ratio(sec.get("s3_versioning_ratio", 0.0))),
        ("RDS instances not public",      invert(sec.get("rds_public_instance_ratio", 0.0))),
        ("RDS public snapshots",          penalty(sec.get("rds_public_snapshot_count", 0), 0.50)),
        # network
        ("Security groups open to world", penalty(sec.get("open_security_group_count", 0), 0.10)),
        ("VPC flow log coverage",         ratio(sec.get("vpc_flow_logs_ratio", 0.0))),
        ("EBS encryption by default",     flag(sec.get("ebs_encryption_by_default"))),
        # detection
        ("GuardDuty enabled",             flag(sec.get("guardduty_enabled"))),
        ("IAM Access Analyzer active",    flag(sec.get("access_analyzer_active"))),
        ("Security Hub enabled",          flag(sec.get("security_hub_enabled"))),
        # S3 hardening
        ("S3 TLS enforced",               ratio(sec.get("s3_tls_enforced_ratio", 0.0))),
        ("S3 ACLs disabled",              ratio(sec.get("s3_acl_disabled_ratio", 0.0))),
        # EC2 patch surface
        ("EC2 deprecated AMIs",           invert(sec.get("deprecated_ami_ratio", 0.0))),
    ]
    return avg(signals), signals


def scoreReliability(rel: dict) -> tuple[float, list]:
    signals = [
        # audit trail
        ("CloudTrail enabled",            flag(rel.get("cloudtrail_enabled"))),
        ("Multi-region CloudTrail",       flag(rel.get("cloudtrail_multiregion"))),
        ("AWS Config recorder active",    flag(rel.get("config_recorder_active"))),
        # recovery
        ("AWS Backup plans configured",   flag(rel.get("backup_plans_exist"))),
        ("RDS automated backups",         ratio(rel.get("rds_backup_enabled_ratio", 0.0))),
        # redundancy
        ("EC2 multi-AZ deployment",       na(rel.get("multi_az_instances"), flag)),
        ("RDS multi-AZ deployment",       ratio(rel.get("rds_multi_az_ratio", 0.0))),
        # data lifecycle
        ("S3 lifecycle policies",         penalty(rel.get("s3_buckets_missing_lifecycle", 0), 0.05)),
        # EKS health
        ("EKS cluster health",            penalty(rel.get("eks_cluster_failure_count", 0), 0.50)),
        ("EKS node group health",         penalty(rel.get("eks_nodegroup_failure_count", 0), 0.25)),
    ]
    return avg(signals), signals


def scoreOperationalExcellence(ops: dict) -> tuple[float, list]:
    signals = [
        # logging
        ("CloudTrail log validation",     flag(ops.get("trail_log_validation"))),
        ("CloudTrail → CloudWatch",       flag(ops.get("cloudtrail_cloudwatch_logs"))),
        # observability
        ("CloudWatch alarms configured",  capped(ops.get("cloudwatch_alarm_count", 0), 10)),
        ("AWS Config rules defined",      capped(ops.get("config_rule_count", 0), 20)),
        # maturity
        ("Account operational maturity",  logAge(ops.get("account_age_days", 1))),
        # hygiene
        ("No unattached EBS volumes",     penalty(ops.get("unattached_ebs_count", 0), 0.10)),
        ("No unused Elastic IPs",         penalty(ops.get("unused_elastic_ip_count", 0), 0.20)),
        # S3 observability
        ("S3 access logging",             ratio(ops.get("s3_access_logging_ratio", 0.0))),
        # EKS version currency
        ("EKS version currency",          penalty(ops.get("eks_outdated_cluster_count", 0), 0.33)),
        # EC2 currency
        ("EC2 current generation",        invert(ops.get("old_gen_instance_ratio", 0.0))),
        ("EC2 instance freshness",        invert(ops.get("stale_instance_ratio", 0.0))),
    ]
    return avg(signals), signals


def scorePerformanceEfficiency(prf: dict) -> tuple[float, list]:
    # rds_performance_insights_ratio: treat as N/A when no RDS has PI enabled
    # (ratio=0.0 means "not used", not "failing" — don't penalise the whole pillar)
    pi_raw = prf.get("rds_performance_insights_ratio")
    pi_score = ratio(pi_raw) if pi_raw else None

    signals = [
        ("Auto Scaling groups in use",        na(prf.get("autoscaling_group_count"),              lambda v: flag(v > 0))),
        ("CloudFront distributions deployed", na(prf.get("cloudfront_distribution_count"),        lambda v: flag(v > 0))),
        ("Graviton instances in use",         na(prf.get("graviton_instances_used"),               flag)),
        ("RDS Performance Insights enabled",  pi_score),
    ]
    return avg(signals), signals

SCORE_CURVE = [
    (0.00, 300),
    (0.47, 580),
    (0.61, 670),
    (0.75, 740),
    (0.87, 800),
    (1.00, 850),
]

def rawToScore(rawPct: float) -> int:
    """Interpolate along SCORE_CURVE to convert a raw 0–1 average to a 300–850 score."""
    rawPct = max(0.0, min(1.0, rawPct))
    for i in range(len(SCORE_CURVE) - 1):
        x0, y0 = SCORE_CURVE[i]
        x1, y1 = SCORE_CURVE[i + 1]
        if rawPct <= x1:
            t = (rawPct - x0) / (x1 - x0)
            return int(y0 + t * (y1 - y0))
    return 850


HURTING_THRESHOLD = 0.5
HELPING_THRESHOLD = 0.8


def extractFactors(pillarResults: list[tuple[str, list]]) -> dict:
    allSignals = [
        {"rating": pillar, "check": name, "score": round(value, 2)}
        for pillar, signals in pillarResults
        for name, value in signals
        if value is not None
    ]
    # sort hurting worst-first so the biggest issues appear at the top
    hurting = sorted(
        [s for s in allSignals if s["score"] <= HURTING_THRESHOLD],
        key=lambda s: s["score"],
    )
    helping = sorted(
        [s for s in allSignals if s["score"] >= HELPING_THRESHOLD],
        key=lambda s: s["score"], reverse=True,
    )
    return {"helping": helping, "hurting": hurting}


class StatlerEngine:
    # Weights: Security 35%, Reliability 25%, Ops 25%, Performance 15%

    def evaluate(self, evidence, services_in_use=None):
        sec = _applyServiceFilter(evidence["security, privacy, and compliance"], "security, privacy, and compliance", services_in_use)
        rel = _applyServiceFilter(evidence["reliability"],            "reliability",            services_in_use)
        ops = _applyServiceFilter(evidence["operational_excellence"], "operational_excellence", services_in_use)
        prf = _applyServiceFilter(evidence["performance_efficiency"], "performance_efficiency", services_in_use)

        secScore, secSigs = scoreSecurity(sec)
        relScore, relSigs = scoreReliability(rel)
        opsScore, opsSigs = scoreOperationalExcellence(ops)
        prfScore, prfSigs = scorePerformanceEfficiency(prf)

        weighted = [
            (secScore, 0.35),
            (relScore, 0.25),
            (opsScore, 0.25),
            (prfScore, 0.15),
        ]
        applicable  = [(s, w) for s, w in weighted if s is not None]
        totalWeight = sum(w for _, w in applicable)
        finalPct    = sum(s * w for s, w in applicable) / totalWeight

        def pct(s):
            return round(s * 100) if s is not None else None

        return {
            "score": rawToScore(finalPct),
            "pillars": {
                "Security, Privacy, and Compliance":               pct(secScore),
                "Reliability":            pct(relScore),
                "Operational Excellence": pct(opsScore),
                "Performance Efficiency": pct(prfScore),
            },
            "factors": extractFactors([
                ("Security, Privacy, and Compliance",               secSigs),
                ("Reliability",            relSigs),
                ("Operational Excellence", opsSigs),
                ("Performance Efficiency", prfSigs),
            ]),
        }
