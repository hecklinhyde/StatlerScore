"""
RFC 3161 trusted timestamping for Merkle roots.

Each time a new attestation is appended, the current Merkle root is submitted
to a public Timestamp Authority (TSA). The TSA signs the root hash together
with its own clock, producing a TimeStampResponse (TSR). The TSR is stored
in anchors.json alongside the root it covers.

This proves the log state existed at a specific point in time, independently
of the bureau. Even if the bureau is later compromised, the TSA's signature
on the root cannot be forged or backdated.

Stamping:    POST root bytes → TSA → TSR (DER, base64-stored)
Verification: openssl ts -verify -in tsr.der -data root.dat -CAfile system-ca

TSA: DigiCert (http://timestamp.digicert.com)
     - Free, high-availability, widely trusted
     - Certificate is included in the TSR so openssl can verify without
       a separately downloaded CA cert
"""

import base64
import os
import subprocess
import tempfile

import rfc3161ng
from pyasn1.codec.der import encoder

TSA_URL = os.getenv("TSA_URL", "http://timestamp.digicert.com")


def stampRoot(root: str) -> dict:
    """
    Submit the Merkle root to the TSA and return the anchor record.
    The TSR and TST are base64-encoded for JSON storage.
    Raises on network failure or non-success TSA status.
    """
    data        = root.encode()
    timestamper = rfc3161ng.RemoteTimestamper(
        TSA_URL, hashname="sha256", include_tsa_certificate=True
    )
    tsr       = timestamper(data=data, return_tsr=True, include_tsa_certificate=True)
    tsr_bytes = encoder.encode(tsr)
    tst_bytes = encoder.encode(tsr["timeStampToken"])
    tsaTime   = rfc3161ng.get_timestamp(tst_bytes)

    return {
        "tsa_url":  TSA_URL,
        "tsa_time": tsaTime.isoformat() if tsaTime else None,
        "tsr_b64":  base64.b64encode(tsr_bytes).decode(),
        "tst_b64":  base64.b64encode(tst_bytes).decode(),
    }


def verifyAnchor(root: str, tsrB64: str) -> dict:
    """
    Verify a stored TSR against the Merkle root using openssl ts.
    Returns verified=True if the TSA signature and data match.
    """
    tsrBytes  = base64.b64decode(tsrB64)
    dataBytes = root.encode()

    tsrFile  = tempfile.NamedTemporaryFile(delete=False, suffix=".tsr")
    dataFile = tempfile.NamedTemporaryFile(delete=False, suffix=".dat")
    try:
        tsrFile.write(tsrBytes);  tsrFile.close()
        dataFile.write(dataBytes); dataFile.close()

        result = subprocess.run(
            [
                "openssl", "ts", "-verify",
                "-in",      tsrFile.name,
                "-data",    dataFile.name,
                "-CAfile",  "/etc/ssl/certs/ca-certificates.crt",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        verified = result.returncode == 0
        return {
            "verified": verified,
            "message":  result.stdout.strip() or result.stderr.strip(),
        }
    except subprocess.TimeoutExpired:
        return {"verified": False, "message": "openssl verification timed out."}
    finally:
        os.unlink(tsrFile.name)
        os.unlink(dataFile.name)
