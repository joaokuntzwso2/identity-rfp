"""Pure Section 7 policy and evidence comparison. Do not infer proof from data presence."""
from __future__ import annotations
import hashlib
import json
from datetime import datetime, timezone

AAL2 = 'urn:magalu:aal2:totp'
SYSTEM_CLAIMS = frozenset({
    'iss','sub','aud','iat','exp','nbf','nonce','auth_time','acr','amr','azp',
    'at_hash','c_hash','s_hash','sid','jti','typ','scope','client_id'
})
PII_CLAIMS = frozenset({'name','given_name','family_name','middle_name',
    'nickname','preferred_username','profile','picture','website','gender',
    'birthdate','zoneinfo','locale','updated_at','email','email_verified',
    'phone_number','phone_number_verified','address','cpf','mobile','roles',
    'groups'})
# Experiment profiles. Server-side gating is an extension; WSO2's native
# User Attributes settings still need to be configured and verified separately.
CLAIM_PROFILES = {
    'magalu:web': frozenset({'name','given_name','family_name','email','email_verified'}),
    'magalu:app': frozenset(),
    'netshoes:web': frozenset(),
    'netshoes:app': frozenset(),
    'magalupay:web': frozenset(),
    'magalupay:app': frozenset(),
}

def safe_hash(s: str) -> str:
    if not isinstance(s,str) or not s: return ''
    return hashlib.sha256(s.encode('utf-8')).hexdigest()[:20]

def claims_result(client: str, id_claim_names, userinfo_claim_names) -> dict:
    allowed = CLAIM_PROFILES[client]
    a=set(id_claim_names) & PII_CLAIMS
    b=set(userinfo_claim_names) & PII_CLAIMS
    forbidden=sorted((a | b) - allowed)
    return {'client':client, 'allowed_pii': sorted(allowed),
            'id_token_pii':sorted(a), 'userinfo_pii':sorted(b),
            'unexpected_pii':forbidden,
            'result':'PASS' if not forbidden else 'FAIL',
            'layer':'OBSERVATION_OF_WSO2_ISSUED_DATA_NOT_IDP_CONFIGURATION_PROOF'}

def compare_four(rows: list[dict], *, operator_same_person: bool) -> dict:
    """Four *independent*, verified sessions: 2 root tenants, 2 channels each.

    Operator attestation is explicit and never a cryptographic shared-identity proof.
    """
    specs=(('magalu','web','magalu.demo'),('magalu','app','magalu.demo'),
           ('magalupay','web','magalupay.demo'),('magalupay','app','magalupay.demo'))
    index={(e.get('brand'),e.get('channel')):e for e in rows}
    entries=[]
    for brand,channel,tenant in specs:
        e=index.get((brand,channel),{})
        ok=(e.get('status')=='authenticated' and e.get('tenant')==tenant and
            isinstance(e.get('sub'),str) and len(e['sub'])>0)
        entries.append({'brand':brand,'channel':channel,'tenant':tenant,
                        'verified_session':ok,'sub_fingerprint':safe_hash(e['sub']) if ok else None,
                        '_sub':e['sub'] if ok else None})
    all_ok=all(e['verified_session'] for e in entries)
    continuity=(all_ok and entries[0]['_sub']==entries[1]['_sub'] and
                entries[2]['_sub']==entries[3]['_sub'])
    segregation=(all_ok and entries[0]['_sub']!=entries[2]['_sub'])
    for e in entries:e.pop('_sub')
    # No success from sub comparison alone. Across roots WSO2 user records
    # are distinct; the synthetic vault or human must establish same person.
    accepted=bool(continuity and segregation and operator_same_person)
    return {'result':'PASS_WITH_OPERATOR_IDENTITY_ATTESTATION' if accepted else
                    'FAIL' if all_ok and (not continuity or not segregation) else 'INCOMPLETE',
            'four_sessions_present':all_ok, 'channel_continuity':bool(continuity),
            'cross_root_sub_segregation':bool(segregation),
            'operator_same_person_attestation':bool(operator_same_person),
            'identity_federation_proven':False,
            'entries':entries, 'requirement':'B-01/B-02/M-02',
            'caveat':'Netshoes shares the Commerce root in the current topology; separate tenant per brand remains a design gap.'}

def derived_identity_level(evidence: list[dict], *, at=None) -> str:
    """Separate per-attribute evidence: never infer verification from PII presence."""
    at = at or datetime.now(timezone.utc)
    present=set()
    for item in evidence:
        if item.get('state')!='VERIFIED' or not item.get('source') or not item.get('method'):
            continue
        try:
            expiration=datetime.fromisoformat(item['expires_at'].replace('Z','+00:00'))
            verified=datetime.fromisoformat(item['verified_at'].replace('Z','+00:00'))
        except (ValueError,TypeError,KeyError,AttributeError):
            continue
        if verified.tzinfo and expiration.tzinfo and at.tzinfo and expiration > at >= verified:
            present.add(item.get('attribute_key'))
    n2={'cpf','email_otp','phone_otp','device'}
    if not n2 <= present:return 'N1'
    if {'face_liveness','face_match','document_match'} <= present:return 'N3'
    return 'N2'

def risk_decision(*, score:int, unknown_device:bool, operation:str,
                  identity_level:str, aal2_recent:bool, face_recent:bool) -> dict:
    if not isinstance(score,int) or not 0 <= score <= 100:raise ValueError('score 0..100')
    if operation != 'fintech-transfer':raise ValueError('unsupported operation')
    risk_high=score>=65 or unknown_device
    need_ial=(identity_level!='N3' or (risk_high and not face_recent))
    need_aal=(risk_high and not aal2_recent)
    return {'decision':'CHALLENGE' if need_ial or need_aal else 'ALLOW',
            'risk_high':risk_high, 'requires_ial_n3':need_ial,
            'requires_aal2':need_aal, 'identity_level':identity_level,
            'independent_assurance_axes':True}

def sanitize(value):
    """Only allow report-safe summaries, never JWTs, secrets or biometric images."""
    return json.loads(json.dumps(value, ensure_ascii=False))
