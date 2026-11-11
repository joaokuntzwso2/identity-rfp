"""Pure domain policy: no persistence of any account-level `verified` flag."""
from datetime import datetime, timezone

N2_REQUIREMENTS = frozenset({'cpf', 'email_otp', 'phone_otp', 'device'})
N3_REQUIREMENTS = N2_REQUIREMENTS | frozenset({'face_liveness'})


def valid_attributes(attributes: list[dict], now: datetime | None = None) -> set[str]:
    now = now or datetime.now(timezone.utc)
    out = set()
    for a in attributes:
        expiry = a.get('expires_at')
        if isinstance(expiry, str):
            expiry = datetime.fromisoformat(expiry.replace('Z', '+00:00'))
        if a.get('state') == 'VERIFIED' and (expiry is None or expiry > now):
            out.add(a['attribute_key'])
    return out


def assurance_level(attributes: list[dict], now: datetime | None = None) -> str:
    valid = valid_attributes(attributes, now)
    if N3_REQUIREMENTS <= valid:
        return 'N3'
    if N2_REQUIREMENTS <= valid:
        return 'N2'
    return 'N1'


def step_up_decision(assurance: str, risk_score: int, operation: str) -> dict:
    """The identity-verification step is an application extension, not an OIDC ACR value."""
    if operation == 'fintech-transfer' and (risk_score >= 65 or assurance != 'N3'):
        return {'decision': 'CHALLENGE', 'required_identity_level': 'N3',
                'required_authentication_level': 'AAL2', 'reason': 'HIGH_RISK_TRANSFER'}
    return {'decision': 'ALLOW', 'required_identity_level': assurance,
            'required_authentication_level': 'AAL1', 'reason': 'POLICY_MET'}


def pairwise_verdict(observations: dict[str, str]) -> dict:
    """Evaluate all SIX real OIDC clients: 3 brands × 2 channels.

    Note: comparisons across different roots are valid only after the private
    seeded-identity vault confirmed the user represents the same test person.
    """
    brands=('magalu','netshoes','magalupay')
    expected={brand+':'+channel for brand in brands for channel in ('web','app')}
    missing=sorted(expected-set(observations))
    if missing:
        return {'pass':False,'status':'INCOMPLETE','missing':missing}
    continuity={b:observations[b+':web']==observations[b+':app'] for b in brands}
    sub_values={observations[b+':web'] for b in brands}
    separation=len(sub_values)==len(brands)
    success=all(continuity.values()) and separation
    return {'pass':success,'status':'PASS' if success else 'FAIL',
            'continuity':continuity,'all_brands_distinct':separation,
            'same_brand_A':continuity['magalu'], 'same_brand_B':continuity['magalupay'],
            'different_brands':separation,'missing':[]}
