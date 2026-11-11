"""Fail-closed external identity-verification attestation, no mock biometrics.

Partner must deliver a JOSE JWT asserting independently performed liveness,
face match and document match. This is an integration contract, NOT a vendor SDK.
Never logs biometric images, credentials, user names or raw attestations.
"""
from __future__ import annotations
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
import jwt
from .s7_policy import AAL2,safe_hash

LOCK=threading.RLock()
DB_PATH=Path(os.getenv('MANIFEST_FILE','/project/generated/manifest.json')).parent/'s7-acceptance.sqlite3'

class NotConfigured(Exception):pass
class VerificationRejected(Exception):pass

def connection():
    DB_PATH.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(str(DB_PATH),timeout=8, isolation_level=None)
    # The SQLite journal contains only pseudonymous references, but still treat
    # all identity/transaction evidence as private local state.
    try: os.chmod(DB_PATH, 0o600)
    except OSError: pass
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('''CREATE TABLE IF NOT EXISTS transactions (
      tx TEXT PRIMARY KEY, issuer_hash TEXT NOT NULL, subject_hash TEXT NOT NULL,
      created INTEGER NOT NULL, deadline INTEGER NOT NULL,
      operation TEXT NOT NULL, risk_score INTEGER NOT NULL,
      unknown_device INTEGER NOT NULL, status TEXT NOT NULL,
      nonce TEXT NOT NULL, aal2_at INTEGER,
      face_at INTEGER, vendor_case_hash TEXT, verified_source TEXT,
      n2_at INTEGER, n2_source TEXT)''')
    db.execute('''CREATE TABLE IF NOT EXISTS used_assertions (
      jti_hash TEXT PRIMARY KEY, expires INTEGER NOT NULL)''')
    return db

def start(tx:str,issuer:str,sub:str,nonce:str,score:int,unknown:bool):
    now=int(time.time())
    with LOCK,connection() as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('''INSERT INTO transactions (tx,issuer_hash,subject_hash,created,
          deadline,operation,risk_score,unknown_device,status,nonce)
          VALUES (?,?,?,?,?,?,?,?,?,?)''',
          (tx,safe_hash(issuer),safe_hash(sub),now,now+900,'fintech-transfer',score,
           int(unknown),'CHALLENGE',nonce))
        db.commit()

def retrieve(tx,issuer,sub):
    with connection() as db:
        row=db.execute('SELECT * FROM transactions WHERE tx=?',(tx,)).fetchone()
    if not row or row['issuer_hash']!=safe_hash(issuer) or row['subject_hash']!=safe_hash(sub):
        raise VerificationRejected('TRANSACTION_IDENTITY_OR_TENANT_MISMATCH')
    if row['deadline'] < time.time():raise VerificationRejected('TRANSACTION_EXPIRED')
    return dict(row)

def record_aal2(tx,issuer,sub,bff):
    row=retrieve(tx,issuer,sub)
    stamp=bff.get('auth_time'); amr=bff.get('amr') or []
    if (bff.get('s7_stepup_tx') != tx or bff.get('acr') != AAL2 or
        'totp' not in [str(m).lower() for m in amr] or
        not isinstance(stamp,(int,float)) or stamp < row['created']-30 or
        time.time()-stamp>300):
        raise VerificationRejected('FRESH_WSO2_AAL2_NOT_PROVEN')
    with LOCK,connection() as db:
        db.execute('UPDATE transactions SET aal2_at=? WHERE tx=?',(int(stamp),tx))
    return {'result':'AAL2_VERIFIED','via':'WSO2_SIGNED_ID_TOKEN_AT_BFF_CALLBACK',
            'acr':AAL2, 'amr':['totp'], 'auth_time':int(stamp)}

def _keys():
    path=os.getenv('S7_PROVIDER_JWKS_FILE','').strip()
    issuer=os.getenv('S7_PROVIDER_ISSUER','').strip()
    audience=os.getenv('S7_PROVIDER_AUDIENCE','').strip()
    if not path or not issuer or not audience:raise NotConfigured('VERIFIER_NOT_CONFIGURED')
    p=Path(path)
    if not p.is_file() or p.stat().st_mode & 0o022 or p.stat().st_size>65536:
        raise NotConfigured('VERIFIER_JWKS_FILE_MISSING_OR_UNSAFE')
    jwks=json.loads(p.read_text())
    if not isinstance(jwks,dict) or not isinstance(jwks.get('keys'),list):
        raise NotConfigured('VERIFIER_JWKS_INVALID')
    return issuer,audience,jwks

def verify_provider_assertion(tx,issuer,sub,assertion:str):
    row=retrieve(tx,issuer,sub)
    iss,aud,jwks=_keys()
    if not isinstance(assertion,str) or len(assertion)>12000:raise VerificationRejected('ATTESTATION_INVALID')
    try:
        header=jwt.get_unverified_header(assertion)
        if header.get('alg') not in ('RS256','ES256') or not header.get('kid'):
            raise VerificationRejected('ATTESTATION_ALGORITHM_REJECTED')
        matches=[k for k in jwks['keys'] if k.get('kid')==header['kid'] and k.get('kty') in ('RSA','EC')]
        if len(matches)!=1:raise VerificationRejected('ATTESTATION_KEY_REJECTED')
        key=jwt.PyJWK.from_dict(matches[0],algorithm=header['alg']).key
        obj=jwt.decode(assertion,key,algorithms=[header['alg']],
                       issuer=iss,audience=aud,leeway=15,
                       options={'require':['iss','aud','iat','nbf','exp','jti','nonce','tx','subject_ref']})
    except jwt.PyJWTError:
        raise VerificationRejected('ATTESTATION_SIGNATURE_OR_CLAIMS_INVALID') from None
    now=int(time.time())
    if not row['n2_at']:raise VerificationRejected('N2_BASELINE_NOT_INDEPENDENTLY_PROVEN')
    if (obj.get('evidence_type')!='N3_FACE_LIVENESS' or
        obj.get('tx')!=tx or obj.get('nonce')!=row['nonce'] or
        obj.get('subject_ref')!=safe_hash(issuer+'|'+sub) or
        not isinstance(obj.get('iat'),int) or abs(now-obj['iat'])>300 or
        not isinstance(obj.get('exp'),int) or obj['exp']-obj['iat']>300):
        raise VerificationRejected('ATTESTATION_TRANSACTION_BINDING_INVALID')
    if (obj.get('decision')!='approved' or obj.get('liveness') is not True or
        obj.get('face_match') is not True or obj.get('document_match') is not True or
        not isinstance(obj.get('vendor_case_id'),str) or not obj['vendor_case_id']):
        raise VerificationRejected('INDEPENDENT_LIVENESS_FACE_DOCUMENT_NOT_VERIFIED')
    # Evidence contracts demand a *real* external verification. Do not accept
    # assertions signed by demo keys or fixtures. Operator config is out-of-band.
    used=safe_hash(iss+'|'+obj['jti'])
    with LOCK,connection() as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('DELETE FROM used_assertions WHERE expires < ?', (now,))
        try:
            db.execute('INSERT INTO used_assertions (jti_hash,expires) VALUES (?,?)',
                       (used,int(obj['exp'])))
        except sqlite3.IntegrityError:
            db.rollback();raise VerificationRejected('ATTESTATION_REPLAY')
        db.execute('''UPDATE transactions SET face_at=?, vendor_case_hash=?,
                   verified_source=? WHERE tx=?''',
                   (now,safe_hash(obj['vendor_case_id']),iss,tx))
        db.commit()
    return {'result':'EXTERNAL_N3_EVIDENCE_VERIFIED','provider':iss,
            'signals':['liveness','face_match','document_match'],
            'jti_replay_protection':'PERSISTED','case_fingerprint':safe_hash(obj['vendor_case_id']),
            'scope':'APPLICATION_VERIFIER_EVIDENCE_NOT_A_WSO2_IAL_TOKEN_CLAIM'}

def decision(tx,issuer,sub):
    r=retrieve(tx,issuer,sub)
    aal=bool(r['aal2_at'] and time.time()-r['aal2_at']<=300)
    n2=bool(r['n2_at'] and time.time()-r['n2_at']<=900)
    face=bool(r['face_at'] and time.time()-r['face_at']<=900)
    # For this risk-triggered acceptance journey, both dimensions are mandatory.
    return {'tx':tx,'decision':'ALLOW' if aal and face and n2 else 'CHALLENGE',
            'n2_baseline_verified':n2,'derived_identity_level':'N3' if face and n2 else 'N2' if n2 else 'N1',
            'aal2_recent':aal,'n3_live_provider_verified':face,
            'risk_score':r['risk_score'], 'unknown_device':bool(r['unknown_device']),
            'provider':r['verified_source'] or 'NOT_CONFIGURED_OR_NOT_COMPLETED',
            'transaction_preserved':True, 'data':'SYNTHETIC_TRANSFER',
            'assurance_source':'AAL_FROM_VERIFIED_WSO2_ID_TOKEN__IAL_FROM_EXTERNAL_SIGNED_RESULT'}


def verify_n2_assertion(tx,issuer,sub,assertion:str):
    """Attestation by configured trusted aggregator of independently verified CPF,
    e-mail OTP, phone OTP and device binding. Never treats PII presence as proof.
    The attesting integrator must use real authoritative verifications.
    """
    row=retrieve(tx,issuer,sub)
    iss,aud,jwks=_keys()
    if not isinstance(assertion,str) or len(assertion)>12000:
        raise VerificationRejected('N2_ATTESTATION_INVALID')
    try:
        head=jwt.get_unverified_header(assertion)
        if head.get('alg') not in ('RS256','ES256') or not head.get('kid'):
            raise VerificationRejected('N2_ALGORITHM_INVALID')
        keys=[k for k in jwks['keys'] if k.get('kid')==head['kid'] and k.get('kty') in ('RSA','EC')]
        if len(keys)!=1:raise VerificationRejected('N2_KEY_INVALID')
        key=jwt.PyJWK.from_dict(keys[0],algorithm=head['alg']).key
        obj=jwt.decode(assertion,key,algorithms=[head['alg']],
                       audience=aud,issuer=iss,leeway=15,
                       options={'require':['iss','aud','iat','nbf','exp','jti','nonce','tx','subject_ref']})
    except jwt.PyJWTError:
        raise VerificationRejected('N2_SIGNATURE_INVALID') from None
    now=int(time.time())
    if (obj.get('evidence_type')!='N2_BASELINE' or obj.get('tx')!=tx or
        obj.get('nonce')!=row['nonce'] or obj.get('subject_ref')!=safe_hash(issuer+'|'+sub) or
        not isinstance(obj.get('iat'),int) or abs(now-obj['iat'])>300 or
        not isinstance(obj.get('exp'),int) or obj['exp']-obj['iat']>300):
        raise VerificationRejected('N2_TRANSACTION_BINDING_INVALID')
    evidence=obj.get('evidence')
    if not isinstance(evidence,list) or len(evidence)!=4:
        raise VerificationRejected('N2_REQUIRED_EVIDENCE_MISSING')
    required={
        'cpf':('receita_federal','cpf_registry'),
        'email_otp':('magalu','email_otp'),
        'phone_otp':('magalu','phone_otp'),
        'device':('magalu','device_binding'),
    }
    seen=set()
    for entry in evidence:
        if not isinstance(entry,dict) or entry.get('attribute_key') not in required:
            raise VerificationRejected('N2_UNKNOWN_ATTRIBUTE')
        keyname=entry['attribute_key']
        if keyname in seen or (entry.get('source'),entry.get('method'))!=required[keyname] or \
           entry.get('state')!='VERIFIED' or not isinstance(entry.get('verified_at'),int) or \
           not isinstance(entry.get('expires_at'),int) or \
           not entry['verified_at']<=now<entry['expires_at']:
            raise VerificationRejected('N2_PROVENANCE_OR_VALIDITY_INVALID')
        seen.add(keyname)
    if set(required)!=seen:raise VerificationRejected('N2_EVIDENCE_INCOMPLETE')
    used=safe_hash(iss+'|'+obj['jti'])
    with LOCK,connection() as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('DELETE FROM used_assertions WHERE expires < ?', (now,))
        try:
            db.execute('INSERT INTO used_assertions (jti_hash,expires) VALUES (?,?)',
                       (used,int(obj['exp'])))
        except sqlite3.IntegrityError:
            db.rollback();raise VerificationRejected('ATTESTATION_REPLAY')
        db.execute('UPDATE transactions SET n2_at=?,n2_source=? WHERE tx=?',(now,iss,tx))
        db.commit()
    return {'result':'N2_BASELINE_ATTESTED_BY_TRUSTED_EXTERNAL_SOURCE',
            'attributes_verified':sorted(required),'source':iss,
            'values_disclosed':False,'note':'External bridge must evidence Receita, both real OTPs and device enrollment.'}
