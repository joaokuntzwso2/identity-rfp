from demo.poc_closure_core import ordered_native_acceptance, replay_verdict, seller_policy, tenant_issuer_match


def test_revoke_order_and_denial():
    names = ['NATIVE_CREATED', 'ALLOW', 'NATIVE_REVOKED', 'DENY', 'RECONCILE']
    ev = [{'stage':n, 'link_hash':'h', **({'reason':'NATIVE_REVOKED'} if n=='DENY' else {}),
           **({'custom_revoked':True} if n=='RECONCILE' else {})} for n in names]
    kw = dict(link_hash='h',native_state='REVOKED',custom_state='REVOKED',
              fintech_not_found=True,has_two_catalogs=True)
    assert ordered_native_acceptance(ev,**kw)['result']=='PASS_OBSERVED'
    assert ordered_native_acceptance(ev[:-1],**kw)['result']=='INCOMPLETE'
    assert ordered_native_acceptance(ev,**{**kw,'native_state':'NOT_FOUND'})['result']=='INCOMPLETE'
    ev[3]['reason'] = 'CUSTOM_CONSENT_NOT_ACTIVE'
    assert ordered_native_acceptance(ev,**kw)['result']=='INCOMPLETE'


def test_jwt_assertion_replay():
    assert replay_verdict(200,True,400,False,'invalid_grant')['result']=='PASS_OBSERVED'
    assert replay_verdict(200,True,200,True,'')['result']=='FAIL_OR_INCOMPLETE'
    assert replay_verdict(400,False,400,False,'invalid_grant')['result']=='FAIL_OR_INCOMPLETE'


def test_b2b_policy():
    owner=dict(active=True,role_name='OWNER',is_legal_representative=True)
    employee=dict(active=True,role_name='EMPLOYEE',is_legal_representative=False)
    assert seller_policy(owner,'change-payout-account')['decision']=='ALLOW'
    assert seller_policy(employee,'view-dashboard')['decision']=='ALLOW'
    assert seller_policy(employee,'change-payout-account')['decision']=='DENY'
    assert seller_policy(None,'view-dashboard')['decision']=='DENY'
    assert seller_policy(owner,'delete-all')['decision']=='DENY'


def test_tenant_issuer():
    assert tenant_issuer_match({'iss':'https://is/t/magalu.demo','sub':'a'},'https://is/t/magalu.demo')
    assert not tenant_issuer_match({'iss':'https://is/t/magalupay.demo','sub':'a'},'https://is/t/magalu.demo')
