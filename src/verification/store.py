import fcntl
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.verification.merkle import recordHash


def _write_locked(path, fn):
    with open(path, 'r+') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        records = json.load(f)
        fn(records)
        f.seek(0)
        f.truncate()
        json.dump(records, f, indent=2)

DB_PATH      = Path(__file__).resolve().parent.parent.parent / "data" / "processed" / "attestations.json"
GENESIS_HASH = "0" * 64


class AttestationStore:
    def __init__(self, path: Path = DB_PATH):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("[]")

    def load(self) -> list:
        return json.loads(self.path.read_text())

    def save(self, records: list) -> None:
        self.path.write_text(json.dumps(records, indent=2))

    def getPrevHash(self) -> str:
        """Hash of the last record, or GENESIS_HASH if the log is empty."""
        records = self.load()
        return recordHash(records[-1]) if records else GENESIS_HASH

    def verifyChain(self) -> dict:
        """Walk every record and confirm prev_hash matches the hash of its predecessor."""
        records = self.load()

        if not records:
            return {"valid": True, "length": 0, "message": "Log is empty."}

        if records[0].get("prev_hash", GENESIS_HASH) != GENESIS_HASH:
            return {
                "valid":          False,
                "length":         len(records),
                "broken_at":      0,
                "attestation_id": records[0]["attestation_id"],
                "message":        "Chain broken at genesis — first record has wrong prev_hash.",
            }

        for i in range(1, len(records)):
            expected = recordHash(records[i - 1])
            actual   = records[i].get("prev_hash", "")
            if actual != expected:
                return {
                    "valid":          False,
                    "length":         len(records),
                    "broken_at":      i,
                    "attestation_id": records[i]["attestation_id"],
                    "message":        f"Chain broken at index {i} — prev_hash does not match hash of record {i - 1}.",
                }

        return {
            "valid":   True,
            "length":  len(records),
            "message": f"Chain intact across all {len(records)} record(s).",
        }

    def append(self, record: dict) -> None:
        _write_locked(self.path, lambda records: records.append(record))

    def getById(self, attestationId: str) -> Optional[dict]:
        return next(
            (r for r in self.load() if r["attestation_id"] == attestationId),
            None,
        )

    def getHistory(self, accountId: str) -> list[dict]:
        return [r for r in self.load() if r["account_id"] == accountId]

    def getLatest(self, accountId: str) -> Optional[dict]:
        history = self.getHistory(accountId)
        return history[-1] if history else None

    def allRecords(self) -> list[dict]:
        return self.load()


ORG_PATH    = Path(__file__).resolve().parent.parent.parent / "data" / "processed" / "organizations.json"
ANCHOR_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "processed" / "anchors.json"


class OrgStore:
    def __init__(self, path: Path = ORG_PATH):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("[]")

    def load(self) -> list:
        return json.loads(self.path.read_text())

    def save(self, records: list) -> None:
        self.path.write_text(json.dumps(records, indent=2))

    def create(self, name: str, awsAccountId: Optional[str], contactEmail: Optional[str],
               apiKeyHash: str) -> dict:
        org = {
            "org_id":         str(uuid.uuid4()),
            "name":           name,
            "aws_account_id": awsAccountId,
            "contact_email":  contactEmail,
            "api_key_hash":   apiKeyHash,
            "created_at":     datetime.now(timezone.utc).isoformat(),
        }
        _write_locked(self.path, lambda records: records.append(org))
        return org

    def getById(self, orgId: str) -> Optional[dict]:
        return next((r for r in self.load() if r["org_id"] == orgId), None)

    def getByName(self, name: str) -> Optional[dict]:
        return next((r for r in self.load() if r["name"].lower() == name.lower()), None)

    def getByApiKey(self, apiKeyHash: str) -> Optional[dict]:
        return next((r for r in self.load() if r.get("api_key_hash") == apiKeyHash), None)


class AnchorStore:
    """Persists RFC 3161 timestamp anchors for each Merkle root."""

    def __init__(self, path: Path = ANCHOR_PATH):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("[]")

    def load(self) -> list:
        return json.loads(self.path.read_text())

    def save(self, records: list) -> None:
        self.path.write_text(json.dumps(records, indent=2))

    def append(self, anchor: dict) -> None:
        _write_locked(self.path, lambda records: records.append(anchor))

    def getLatest(self) -> Optional[dict]:
        records = self.load()
        return records[-1] if records else None

    def getByRoot(self, root: str) -> Optional[dict]:
        return next((r for r in self.load() if r["merkle_root"] == root), None)
