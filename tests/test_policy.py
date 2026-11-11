from datetime import datetime,timezone,timedelta
from demo.policy import assurance_level, pairwise_verdict, step_up_decision


def verified(*keys):
    return [{'attribute_key':key,'state':'VERIFIED',
             'expires_at':datetime.now(timezone.utc)+timedelta(days=5)} for key in keys]


def test_ial_invariant():
    assert assurance_level([])=='N1'
    assert assurance_level(verified('cpf','email_otp','phone_otp','device'))=='N2'
    assert assurance_level(verified('cpf','email_otp','phone_otp','device','face_liveness'))=='N3'
    assert assurance_level(verified('cpf','email_otp','phone_otp','device','face_liveness','address'))=='N3'


def test_expired_biometric_recomputes_to_n2():
    a=verified('cpf','email_otp','phone_otp','device','face_liveness')
    a[-1]['expires_at']=datetime.now(timezone.utc)-timedelta(minutes=1)
    assert assurance_level(a)=='N2'


def test_policy_does_not_conflate_ial_and_aal():
    decision=step_up_decision('N2',80,'fintech-transfer')
    assert decision['decision']=='CHALLENGE'
    assert decision['required_identity_level']=='N3'
    assert decision['required_authentication_level']=='AAL2'


def test_pairwise_full_matrix():
    ok={'magalu:web':'a','magalu:app':'a','netshoes:web':'c','netshoes:app':'c','magalupay:web':'b','magalupay:app':'b'}
    assert pairwise_verdict(ok)['pass']
    ok['magalupay:app']='a'
    assert pairwise_verdict(ok)['status']=='FAIL'
    assert pairwise_verdict({'magalu:web':'a'})['status']=='INCOMPLETE'
