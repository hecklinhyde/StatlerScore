"""
Statler Score Bureau — FastAPI service

Start with:
    uvicorn src.verification.api:app --reload --port 8000

Authentication
--------------
Protected endpoints require:  Authorization: Bearer <api_key>
The api_key is returned once at POST /organizations and never again.

Endpoints
---------
POST /organizations               Register an org — returns org_id and api_key.
GET  /organizations/{org_id}      Look up a registered org.
POST /attest              [auth]  Score evidence and return a signed attestation.
GET  /score/{id}/latest   [auth]  Most recent score with expiry info.
GET  /score/{id}/status   [auth]  Lightweight expiry check.
GET  /history/{id}        [auth]  Full attestation history.
GET  /verify/{id}                 Verify the HMAC signature on one record.
GET  /chain/verify                Verify hash-chain integrity across the full log.
GET  /merkle/root                 Current Merkle root + latest RFC 3161 anchor.
GET  /proof/{id}                  Merkle inclusion proof for one attestation.
GET  /merkle/anchor/latest        Full anchor record (TSR bytes included).
GET  /merkle/anchor/verify/{root} Re-verify a stored TSR against the root via openssl.
"""

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Any, Optional

from src.scoring.score import CloudCreditEngine
from src.verification.attestor import createAttestation, verifyAttestation, expiryInfo
from src.verification.auth import generateApiKey, hashApiKey, requireOrg
from src.verification.store import AttestationStore, OrgStore, AnchorStore
from src.verification import merkle
from src.verification import timestamp

app     = FastAPI(
    title       = "Cloud Credit Bureau",
    description = "Independent attestation authority for cloud security posture scores.",
    version     = "2.0.0",
)
engine  = CloudCreditEngine()
store   = AttestationStore()
orgs    = OrgStore()
anchors = AnchorStore()


class OrgRequest(BaseModel):
    name:           str           = Field(..., description="Organisation name.")
    aws_account_id: Optional[str] = Field(None, description="AWS account ID (optional).")
    contact_email:  Optional[str] = Field(None, description="Contact email (optional).")

class AttestRequest(BaseModel):
    account_id: str            = Field(..., description="org_id from POST /organizations.")
    evidence:   dict[str, Any] = Field(..., description="WAF pillar evidence from CloudHarvester.")


@app.post("/organizations", status_code=201, summary="Register an organisation")
def createOrg(req: OrgRequest):
    """
    Register your organisation. Returns a unique org_id and a one-time api_key.
    Store the api_key securely — it will not be shown again.
    Use the org_id as account_id in all future /attest calls.
    Names must be unique.
    """
    if orgs.getByName(req.name):
        raise HTTPException(status_code=409, detail=f"Organisation '{req.name}' is already registered.")
    rawKey = generateApiKey()
    org    = orgs.create(req.name, req.aws_account_id, req.contact_email, hashApiKey(rawKey))
    return {
        **{k: v for k, v in org.items() if k != "api_key_hash"},
        "api_key":      rawKey,
        "api_key_note": "Save this key — it will not be shown again.",
    }


@app.get("/organizations/{org_id}", summary="Look up a registered organisation")
def getOrg(org_id: str):
    org = orgs.getById(org_id)
    if not org:
        raise HTTPException(status_code=404, detail=f"Organisation '{org_id}' not found.")
    return {k: v for k, v in org.items() if k != "api_key_hash"}


@app.post("/attest", status_code=201, summary="Submit evidence for scoring")
def attest(req: AttestRequest, org: dict = Depends(requireOrg)):
    """
    Core bureau operation — requires Bearer token.
    1. Verifies the API key belongs to the account_id being attested.
    2. Scores evidence through the weighted WAF formula.
    3. Signs the attestation over (evidence_hash | timestamp | account_id | prev_hash | valid_until).
    4. Appends to the log and returns the full attestation.
    """
    if req.account_id != org["org_id"]:
        raise HTTPException(status_code=403, detail="API key does not match the account_id in the request.")

    try:
        result = engine.evaluate(req.evidence)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid evidence payload: {type(exc).__name__}: {exc}")

    prevHash    = store.getPrevHash()
    attestation = createAttestation(
        accountId = req.account_id,
        evidence  = req.evidence,
        score     = result["score"],
        pillars   = result["pillars"],
        prevHash  = prevHash,
        factors   = result["factors"],
    )
    store.append(attestation)

    # Anchor the new Merkle root with an RFC 3161 timestamp.
    # Wrapped in try/except so a TSA outage never blocks an attestation.
    records  = store.allRecords()
    root     = merkle.merkleRoot(records)
    anchorRef = None
    try:
        anchorData = timestamp.stampRoot(root)
        anchor = {
            "merkle_root":   root,
            "total_records": len(records),
            "anchored_at":   attestation["timestamp"],
            **anchorData,
        }
        anchors.append(anchor)
        anchorRef = {"tsa_url": anchor["tsa_url"], "tsa_time": anchor["tsa_time"]}
    except Exception:
        pass

    return {**attestation, "anchor": anchorRef}


@app.get("/score/{account_id}/latest", summary="Latest score with expiry information")
def latestScore(account_id: str, org: dict = Depends(requireOrg)):
    """Returns the most recent attestation plus an expiry block — requires Bearer token."""
    if account_id != org["org_id"]:
        raise HTTPException(status_code=403, detail="Access denied.")
    record = store.getLatest(account_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"No attestations found for account '{account_id}'.")
    return {**record, "expiry": expiryInfo(record)}


@app.get("/score/{account_id}/status", summary="Lightweight expiry status check")
def scoreStatus(account_id: str, org: dict = Depends(requireOrg)):
    """Returns only expiry info for the latest attestation — requires Bearer token."""
    if account_id != org["org_id"]:
        raise HTTPException(status_code=403, detail="Access denied.")
    record = store.getLatest(account_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"No attestations found for account '{account_id}'.")
    info = expiryInfo(record)
    return {
        "account_id":     account_id,
        "attestation_id": record["attestation_id"],
        "score":          record["score"],
        "verdict":        record["verdict"],
        **info,
    }


@app.get("/history/{account_id}", summary="Full attestation history for an account")
def history(account_id: str, org: dict = Depends(requireOrg)):
    """Returns all attestations for the account — requires Bearer token."""
    if account_id != org["org_id"]:
        raise HTTPException(status_code=403, detail="Access denied.")
    records = store.getHistory(account_id)
    if not records:
        raise HTTPException(status_code=404, detail=f"No history found for account '{account_id}'.")
    return {"account_id": account_id, "count": len(records), "attestations": records}


@app.get("/verify/{attestation_id}", summary="Verify HMAC signature of one attestation")
def verify(attestation_id: str):
    """
    Public endpoint — re-derives the HMAC-SHA256 signature and compares in constant time.
    valid: true means the record is authentic and unmodified since issuance.
    """
    record = store.getById(attestation_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Attestation '{attestation_id}' not found.")
    valid, message = verifyAttestation(record)
    return {
        "attestation_id": attestation_id,
        "account_id":     record["account_id"],
        "timestamp":      record["timestamp"],
        "score":          record["score"],
        "valid":          valid,
        "message":        message,
    }


@app.get("/chain/verify", summary="Verify the hash chain across the full log")
def chainVerify():
    """
    Public endpoint — walks every record and confirms prev_hash equals SHA-256 of the
    preceding record. Catches deletions, insertions, and reorderings.
    """
    return store.verifyChain()


@app.get("/merkle/root", summary="Current Merkle root of the full log")
def merkleRootEndpoint():
    """
    Public endpoint — returns the Merkle root over all attestation records plus the
    most recent RFC 3161 anchor so third parties know it has been externally timestamped.
    """
    records      = store.allRecords()
    root         = merkle.merkleRoot(records)
    latestAnchor = anchors.getLatest()
    anchorSummary = None
    if latestAnchor:
        anchorSummary = {
            "merkle_root": latestAnchor["merkle_root"],
            "tsa_url":     latestAnchor["tsa_url"],
            "tsa_time":    latestAnchor["tsa_time"],
            "anchored_at": latestAnchor["anchored_at"],
        }
    return {
        "root":           root,
        "total_records":  len(records),
        "latest_anchor":  anchorSummary,
    }


@app.get("/merkle/anchor/latest", summary="Full latest RFC 3161 anchor record")
def anchorLatest():
    """
    Public endpoint — returns the most recent anchor including the base64-encoded
    TSR bytes. Use the tsr_b64 field with openssl ts -verify for full cryptographic
    verification independent of this API.
    """
    anchor = anchors.getLatest()
    if not anchor:
        raise HTTPException(status_code=404, detail="No anchors found. Submit an attestation first.")
    return anchor


@app.get("/merkle/anchor/verify/{root}", summary="Re-verify a stored RFC 3161 anchor")
def anchorVerify(root: str):
    """
    Public endpoint — retrieves the stored TSR for the given Merkle root and
    re-runs openssl ts -verify to confirm the TSA signature is still valid.
    """
    anchor = anchors.getByRoot(root)
    if not anchor:
        raise HTTPException(status_code=404, detail=f"No anchor found for root '{root}'.")
    result = timestamp.verifyAnchor(root, anchor["tsr_b64"])
    return {
        "merkle_root": root,
        "tsa_url":     anchor["tsa_url"],
        "tsa_time":    anchor["tsa_time"],
        **result,
    }


@app.get("/proof/{attestation_id}", summary="Merkle inclusion proof for one attestation")
def proof(attestation_id: str):
    """
    Public endpoint — returns the minimal set of sibling hashes needed to prove this
    attestation is in the log without seeing any other records.
    """
    records = store.allRecords()
    result  = merkle.merkleProof(records, attestation_id)

    if result is None:
        raise HTTPException(status_code=404, detail=f"Attestation '{attestation_id}' not found.")

    verified = merkle.verifyProof(result["leaf_hash"], result["proof_steps"], result["root"])
    return {**result, "verified": verified}
