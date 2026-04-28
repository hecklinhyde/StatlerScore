import hashlib
import secrets

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer()


def generateApiKey() -> str:
    return "ssb_" + secrets.token_hex(32)


def hashApiKey(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def requireOrg(credentials: HTTPAuthorizationCredentials = Depends(_bearer)):
    from src.verification.store import OrgStore
    keyHash = hashApiKey(credentials.credentials)
    org = OrgStore().getByApiKey(keyHash)
    if not org:
        raise HTTPException(status_code=401, detail="Invalid API key.")
    return org
