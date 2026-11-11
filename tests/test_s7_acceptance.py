"""Offline security contract tests; do NOT count as WSO2 or biometric live acceptance."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json,time,uuid
import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from demo.s7_policy import (compare_four,claims_result,derived_identity_level,
                             risk_decision,AAL2,safe_hash)
from demo import s7_assurance as sa


def test_four_verified_sessions_and_operator_confirmation():
    rows=[{'brand':b,'channel':ch,'tenant':tenant,'status':'authenticated','sub':sub}
          for b,tenant,sub in [('magalu','magalu.demo','a'),('magalupay','magalupay.demo','b')]
          for ch in ('web','app')]
    a=compare_four(rows,operator_same_person=False)
    assert a['result']=='INCOMPLETE'
    b=compare_four(rows,operator_same_person=True)
    assert b['result']=='PASS_WITH_OPERATOR_IDENTITY_ATTESTATION'
    assert b['identity_federation_proven'] is False
    rows[1]['sub']='changed'
    assert compare_four(rows,operator_same_person=True)['result']=='FAIL'

def test_client_claims_are_different_and_unexpected_rejected():
    assert claims_result('magalu:web',['sub','iss','email'],['sub','email'])['result']=='PASS'
    assert claims_result('magalu:app',['sub'],['sub'])['result']=='PASS'
    assert claims_result('magalu:app',['sub','email'],['sub'])['result']=='FAIL'
    assert claims_result('magalu:web',['sub'],['sub','cpf'])['unexpected_pii']==['cpf']

def test_level_derivation_requires_provenance_and_expiry():
    at=datetime.now(timezone.utc)
    before=(at-timedelta(days=1)).isoformat()
    after=(at+timedelta(days=1)).isoformat()
    attrs=[dict(attribute_key=x,source='external',method='verified',state='VERIFIED',verified_at=before,expires_at=after)
           for x in ('cpf','email_otp','phone_otp','device')]
    assert derived_identity_level(attrs,at=at)=='N2'
    attrs.extend(dict(attribute_key=x,source='vendor',method=x,
                      state='VERIFIED',verified_at=before,expires_at=after)
                 for x in ('face_liveness','face_match','document_match'))
    assert derived_identity_level(attrs,at=at)=='N3'
    attrs[-3]['expires_at']=before
    assert derived_identity_level(attrs,at=at)=='N2'
    attrs[0]['source']=''
    assert derived_identity_level(attrs,at=at)=='N1'

def test_risk_policy_preserves_separate_identity_and_authentication_axes():
    d=risk_decision(score=85,unknown_device=True,operation='fintech-transfer',
                    identity_level='N2',aal2_recent=False,face_recent=False)
    assert d['requires_ial_n3'] and d['requires_aal2']
    assert d['decision']=='CHALLENGE'
    with pytest.raises(ValueError):risk_decision(score=120,unknown_device=False,operation='fintech-transfer',identity_level='N2',aal2_recent=False,face_recent=False)

def _environment(tmp_path,monkeypatch):
    sa.DB_PATH=tmp_path/'proof.sqlite3'
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk['kid']='real-provider-key-test-fixture'
    p=tmp_path/'public-jwks.json';p.write_text(json.dumps({'keys':[jwk]}))
    monkeypatch.setenv('S7_PROVIDER_JWKS_FILE',str(p))
    monkeypatch.setenv('S7_PROVIDER_ISSUER','https://real-verifier.example.test')
    monkeypatch.setenv('S7_PROVIDER_AUDIENCE','magalu-ciam-rfp-s7')
    tx=str(uuid.uuid4());nonce='test-random-binding'
    iss='https://is.example.test/t/magalupay.demo/oauth2/token';sub='pairwise-sub'
    sa.start(tx,iss,sub,nonce,85,True)
    def sign(obj):
        now=int(time.time())
        body={'iss':'https://real-verifier.example.test','aud':'magalu-ciam-rfp-s7',
              'iat':now,'nbf':now-1,'exp':now+240,'jti':str(uuid.uuid4()),
              'tx':tx,'nonce':nonce,'subject_ref':safe_hash(iss+'|'+sub),**obj}
        return jwt.encode(body,key,algorithm='RS256',headers={'kid':jwk['kid']})
    return tx,iss,sub,sign

def test_real_signature_required_n2_then_n3_and_replay(tmp_path,monkeypatch):
    tx,iss,sub,sign=_environment(tmp_path,monkeypatch)
    now=int(time.time())
    entries=[{'attribute_key':name,'state':'VERIFIED','source':src,'method':method,
              'verified_at':now-100,'expires_at':now+600}
             for name,src,method in [('cpf','receita_federal','cpf_registry'),
               ('email_otp','magalu','email_otp'),('phone_otp','magalu','phone_otp'),
               ('device','magalu','device_binding')]]
    with pytest.raises(sa.VerificationRejected):
        sa.verify_provider_assertion(tx,iss,sub,sign({'evidence_type':'N3_FACE_LIVENESS',
           'decision':'approved','liveness':True,'face_match':True,'document_match':True,
           'vendor_case_id':'case1'}))
    n2=sign({'evidence_type':'N2_BASELINE','evidence':entries})
    assert sa.verify_n2_assertion(tx,iss,sub,n2)['result'].startswith('N2_BASELINE')
    with pytest.raises(sa.VerificationRejected,match='REPLAY'):
        sa.verify_n2_assertion(tx,iss,sub,n2)
    assert sa.decision(tx,iss,sub)['decision']=='CHALLENGE'
    n3=sign({'evidence_type':'N3_FACE_LIVENESS','decision':'approved',
             'liveness':True,'face_match':True,'document_match':True,'vendor_case_id':'case1'})
    assert sa.verify_provider_assertion(tx,iss,sub,n3)['result']=='EXTERNAL_N3_EVIDENCE_VERIFIED'
    assert sa.decision(tx,iss,sub)['decision']=='CHALLENGE'
    sa.record_aal2(tx,iss,sub,{'s7_stepup_tx':tx,'acr':AAL2,'amr':['pwd','totp'],'auth_time':int(time.time())})
    d=sa.decision(tx,iss,sub)
    assert d['decision']=='ALLOW' and d['derived_identity_level']=='N3' and d['aal2_recent']
    with pytest.raises(sa.VerificationRejected):sa.retrieve(tx,iss,'wrong-sub')

def test_no_biometric_source_means_no_success(tmp_path,monkeypatch):
    tx,iss,sub,sign=_environment(tmp_path,monkeypatch)
    assert sa.decision(tx,iss,sub)['decision']=='CHALLENGE'
    invalid=sign({'evidence_type':'N3_FACE_LIVENESS','decision':'approved',
                  'liveness':False,'face_match':True,'document_match':True,
                  'vendor_case_id':'case1'})
    with pytest.raises(sa.VerificationRejected):sa.verify_provider_assertion(tx,iss,sub,invalid)

def test_installer_prompts_wso2_for_totp_during_new_stepup():
    """Use live source layout; formatting changes must not break the installer."""
    import importlib.util
    from pathlib import Path
    root=Path(__file__).resolve().parents[1]
    file=root/'scripts'/'install-s7-acceptance.py'
    spec=importlib.util.spec_from_file_location('s7_installer',file)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    source=(root/'demo'/'storefront.py').read_text()
    changed=mod.changes_storefront(source)
    assert "if purpose in ('approval','s7_stepup')" in changed
    assert "s['s7_stepup_tx']=pending['request_id']" in changed
    assert "@app.get('/api/s7/evidence')" in changed
    assert "'id_token_claim_names'" in changed
    assert mod.changes_storefront(changed)==changed


def test_no_fake_pass_for_empty_claim_profiles():
    """Empty claim output is not proof of differentiated disclosure."""
    a=claims_result('magalu:web',['sub','iss'],['sub'])
    b=claims_result('magalu:app',['sub','iss'],['sub'])
    assert a['result']=='PASS' and b['result']=='PASS'
    assert not (set(a['id_token_pii']+a['userinfo_pii']) - set(b['id_token_pii']+b['userinfo_pii']))

def test_real_provider_configuration_rejects_private_signing_keys():
    import importlib.util
    from pathlib import Path
    file=Path(__file__).resolve().parents[1]/'scripts'/'configure-s7-provider.py'
    spec=importlib.util.spec_from_file_location('s7_provider_configuration',file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    with pytest.raises(ValueError,match='PRIVATE_KEY_MATERIAL_REJECTED'):
        module.check_jwks(json.dumps({'keys':[{'kty':'RSA','kid':'private','n':'abc','e':'AQAB','d':'private'}]}).encode())
    assert module.check_jwks(json.dumps({'keys':[{'kty':'RSA','kid':'public','n':'abc','e':'AQAB'}]}).encode())['keys'][0]['kid']=='public'
