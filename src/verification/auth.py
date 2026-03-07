"""
API key authentication for the Cloud Credit Bureau.

Keys are generated once at org registration and never stored in plaintext.
Only the SHA-256 hash is persisted. On each request the presented key is
hashed and compared, so even a full database dump reveals no usable keys.

Key format: ccb_<64 hex chars>
The ccb_ prefix makes bureau keys easy to spot in logs and configs.
"""

import hashlib
import secrets

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer()


def generateApiKey() -> str:
    return "ccb_" + secrets.token_hex(32)


def hashApiKey(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def requireOrg(credentials: HTTPAuthorizationCredentials = Depends(_bearer)):
    """
    FastAPI dependency. Resolves a Bearer token to the org it belongs to.
    Raises 401 if the key is missing or unrecognised.
    Import and use as: org: dict = Depends(requireOrg)
    """
    from src.verification.store import OrgStore
    keyHash = hashApiKey(credentials.credentials)
    org = OrgStore().getByApiKey(keyHash)
    if not org:
        raise HTTPException(status_code=401, detail="Invalid API key.")
    return org
