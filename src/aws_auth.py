import os
import boto3
from botocore.exceptions import NoCredentialsError, ClientError


def setup_aws_session() -> boto3.Session:
    """
    Builds a boto3 Session. Resolution order:

    1. AWS_PROFILE env var  — uses a named CLI profile (recommended for SSO)
    2. Explicit env vars    — AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY [+ AWS_SESSION_TOKEN]

    Optional: AWS_DEFAULT_REGION (defaults to us-east-1)

    Raises SystemExit with a clear message if credentials are missing or invalid.
    """
    profile = os.getenv("AWS_PROFILE")
    region  = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

    if profile:
        session = boto3.Session(profile_name=profile, region_name=region)
    else:
        key_id = os.getenv("AWS_ACCESS_KEY_ID")
        secret = os.getenv("AWS_SECRET_ACCESS_KEY")
        token  = os.getenv("AWS_SESSION_TOKEN")

        if not key_id or not secret:
            raise SystemExit(
                "AWS credentials not found. Either:\n"
                "  export AWS_PROFILE=<your-cli-profile>   # recommended for SSO\n"
                "or:\n"
                "  export AWS_ACCESS_KEY_ID=...\n"
                "  export AWS_SECRET_ACCESS_KEY=...\n"
                "  export AWS_SESSION_TOKEN=...            # for temporary credentials"
            )

        session = boto3.Session(
            aws_access_key_id     = key_id,
            aws_secret_access_key = secret,
            aws_session_token     = token,
            region_name           = region,
        )

    # Sanity-check — catches expired tokens before the full collection run
    try:
        session.client("sts").get_caller_identity()
    except (NoCredentialsError, ClientError) as exc:
        raise SystemExit(f"AWS credential check failed: {exc}")

    return session
