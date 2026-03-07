"""
history.py 
New code should import AttestationStore directly from src.verification.store.
"""

from src.verification.store import AttestationStore

# Legacy alias so existing references to CreditBureau still resolve.
CreditBureau = AttestationStore
