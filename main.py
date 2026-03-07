"""
Submits AWS evidence to the Cloud Credit Bureau and prints the signed report.

Start the bureau first:
    python -m uvicorn src.verification.api:app --reload --port 8000

Set USE_MOCK=1 to use the built-in mock evidence instead (no AWS credentials needed).
Initial commit of the proram
"""

import os

# Point matplotlib at a minimal config before it initialises, suppressing
# "Bad key" warnings from the outdated system-wide matplotlibrc.
os.environ.setdefault(
    "MATPLOTLIBRC",
    os.path.dirname(os.path.abspath(__file__)),
)
import sys
import requests

from src.aws_auth import setup_aws_session
from src.collectors.cloudharvester import CloudHarvester
from src.reporting.render import generateReport
from src.reporting.visualize import generateScoreImage, generatePillarImage

BUREAU_URL = "http://localhost:8000"
ACCOUNT_ID = os.environ["CCB_ACCOUNT_ID"]
HEADERS    = {"Authorization": f"Bearer {os.environ['CCB_API_KEY']}"}

# ── Evidence collection ───────────────────────────────────────────────────────

if os.getenv("USE_MOCK") == "1":
    print("Using mock evidence (USE_MOCK=1).")
    evidence = {
        'security': {
            'root_mfa_enabled':          True,
            'password_policy_set':       True,
            'guardduty_enabled':         False,
            's3_public_bucket_ratio':    0.1,
            'stale_access_key_ratio':    0.25,
            'iam_user_mfa_ratio':        0.8,
            'imdsv2_enforced_ratio':     0.5,
            'ebs_encryption_by_default': False,
            'access_analyzer_active':    False,
            'security_hub_enabled':      False,
            'vpc_flow_logs_ratio':       0.5,
            's3_versioning_ratio':       0.3,
            'rds_public_instance_ratio': 0.2,
            'iam_wildcard_admin_count':  1,
            'open_security_group_count': 2,
            'rds_public_snapshot_count': 0,
            'deprecated_ami_ratio':      0.2,
            's3_tls_enforced_ratio':     0.4,
            's3_acl_disabled_ratio':     0.5,
        },
        'reliability': {
            'cloudtrail_enabled':           True,
            'cloudtrail_multiregion':       False,
            'config_recorder_active':       True,
            'backup_plans_exist':           False,
            'multi_az_instances':           True,
            'rds_backup_enabled_ratio':     0.75,
            'rds_multi_az_ratio':           0.5,
            's3_buckets_missing_lifecycle': 4,
            'eks_cluster_failure_count':    0,
            'eks_nodegroup_failure_count':  1,
        },
        'operational_excellence': {
            'trail_log_validation':       True,
            'cloudwatch_alarm_count':     5,
            'config_rule_count':          8,
            'account_age_days':           365,
            'cloudtrail_cloudwatch_logs': False,
            'unattached_ebs_count':       3,
            'unused_elastic_ip_count':    1,
            's3_access_logging_ratio':    0.3,
            'eks_outdated_cluster_count': 1,
            'old_gen_instance_ratio':     0.3,
            'stale_instance_ratio':       0.2,
        },
        'performance_efficiency': {
            'autoscaling_group_count':       2,
            'cloudfront_distribution_count': 1,
            'graviton_instances_used':       False,
        },
    }
else:
    print("Collecting live AWS evidence...")
    session  = setup_aws_session()
    evidence = CloudHarvester(session).collect()
    print("Collection complete.")

# ── Submit to bureau ──────────────────────────────────────────────────────────

try:
    prevResponse  = requests.get(f"{BUREAU_URL}/score/{ACCOUNT_ID}/latest", headers=HEADERS, timeout=5)
    previousScore = prevResponse.json()["score"] if prevResponse.status_code == 200 else None

    response = requests.post(
        f"{BUREAU_URL}/attest",
        headers=HEADERS,
        json={"account_id": ACCOUNT_ID, "evidence": evidence},
        timeout=30,
    )
    response.raise_for_status()
    attestation = response.json()

except requests.exceptions.ConnectionError:
    print(
        "Bureau is offline. Start it with:\n"
        "    python -m uvicorn src.verification.api:app --reload --port 8000\n"
    )
    sys.exit(1)

except requests.exceptions.HTTPError as exc:
    print(f"Bureau returned an error: {exc}\n{response.text}")
    sys.exit(1)

if previousScore is None:
    previousScore = attestation["score"]

print(generateReport(attestation, previousScore=previousScore))

scorePath  = generateScoreImage(attestation,  previousScore=previousScore)
pillarPath = generatePillarImage(attestation, previousScore=previousScore)
print(f"\nImages saved → {scorePath}  |  {pillarPath}")
