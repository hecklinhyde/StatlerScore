import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

SECRET = os.getenv("BUREAU_SECRET", "").encode()
if not SECRET:
    raise RuntimeError("BUREAU_SECRET is not set. Add it to your .env file.")
AGENT_PATH = Path(__file__).resolve().parent.parent / "collectors" / "cloudharvester.py"

TTL_DAYS    = int(os.getenv("SCORE_TTL_DAYS", "90"))
EXPIRY_WARN = 14

GENESIS_HASH = "0" * 64

VERDICTS = [
    (800, "Resilient Posture"),
    (740, "Strong Posture"),
    (670, "Stable Posture"),
    (580, "Accumulating Technical Risk"),
    (0,   "Critical Remediation Required"),
]

def verdictFor(score: int) -> str:
    for threshold, label in VERDICTS:
        if score >= threshold:
            return label
    return "Critical Remediation Required"


def agentHash() -> str:
    """SHA-256 of the harvester source. Changes if the collector is modified."""
    try:
        return hashlib.sha256(AGENT_PATH.read_bytes()).hexdigest()
    except FileNotFoundError:
        return "unavailable"


def evidenceHash(evidence: dict) -> str:
    """Deterministic SHA-256 of the evidence payload."""
    return hashlib.sha256(
        json.dumps(evidence, sort_keys=True, default=str).encode()
    ).hexdigest()


def sign(evHash: str, timestamp: str, accountId: str, prevHash: str,
         validUntil: str = "") -> str:
    if validUntil:
        message = f"{evHash}|{timestamp}|{accountId}|{prevHash}|{validUntil}".encode()
    else:
        message = f"{evHash}|{timestamp}|{accountId}|{prevHash}".encode()
    return hmac.new(SECRET, message, hashlib.sha256).hexdigest()


def createAttestation(
    accountId: str,
    evidence:  dict,
    score:     int,
    pillars:   dict,
    prevHash:  str  = GENESIS_HASH,
    factors:   dict = None,
) -> dict:
    attestationId = str(uuid.uuid4())
    timestamp     = datetime.now(timezone.utc).isoformat()
    validUntil    = (datetime.now(timezone.utc) + timedelta(days=TTL_DAYS)).isoformat()
    evHash        = evidenceHash(evidence)

    record = {
        "attestation_id": attestationId,
        "account_id":     accountId,
        "timestamp":      timestamp,
        "valid_until":    validUntil,
        "prev_hash":      prevHash,
        "agent_hash":     agentHash(),
        "evidence_hash":  evHash,
        "signature":      sign(evHash, timestamp, accountId, prevHash, validUntil),
        "score":          score,
        "pillars":        pillars,
        "verdict":        verdictFor(score),
    }
    if factors is not None:
        record["factors"] = factors
    return record


def verifyAttestation(record: dict) -> tuple[bool, str]:
    """Re-derive the HMAC and compare in constant time."""
    expected = sign(
        record["evidence_hash"],
        record["timestamp"],
        record["account_id"],
        record.get("prev_hash",   GENESIS_HASH),
        record.get("valid_until", ""),
    )
    if hmac.compare_digest(expected, record["signature"]):
        return True, "Signature valid — attestation is authentic and unmodified."
    return False, "Signature mismatch — record may have been tampered with after issuance."


def expiryInfo(record: dict) -> dict:
    validUntilStr = record.get("valid_until")

    if not validUntilStr:
        return {
            "valid_until":    None,
            "days_remaining": None,
            "expired":        None,
            "status":         "no_expiry",
        }

    validUntil    = datetime.fromisoformat(validUntilStr)
    now           = datetime.now(timezone.utc)
    daysRemaining = max(0, (validUntil - now).days)
    expired       = now > validUntil

    if expired:
        status = "expired"
    elif daysRemaining <= EXPIRY_WARN:
        status = "expiring_soon"
    else:
        status = "valid"

    return {
        "valid_until":    validUntilStr,
        "days_remaining": daysRemaining,
        "expired":        expired,
        "status":         status,
    }

