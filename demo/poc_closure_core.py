"""Section 7 acceptance predicates: independent of UI and intentionally fail-closed."""
from __future__ import annotations
from collections.abc import Mapping


def ordered_native_acceptance(events, *, link_hash, native_state, custom_state,
                              fintech_not_found, has_two_catalogs):
    """Only a real, ordered transition with native REVOKED readback can pass.

    The ledger's events are an operator aid; they must be correlated with the
    same link binding and independently fetched current WSO2 state.
    """
    stages = [str(e.get('stage')) for e in events
              if isinstance(e, Mapping) and e.get('link_hash') == link_hash]
    needed = ('NATIVE_CREATED', 'ALLOW', 'NATIVE_REVOKED', 'DENY', 'RECONCILE')
    position = -1
    for stage in needed:
        next_positions = [i for i in range(position + 1, len(stages)) if stages[i] == stage]
        if not next_positions:
            return {'result': 'INCOMPLETE', 'missing_stage': stage, 'observed': stages,
                    'native_readback': native_state, 'custom_state': custom_state}
        position = next_positions[0]
    matching = [e for e in events if isinstance(e, Mapping) and e.get('link_hash') == link_hash]
    # Denial must specifically be due to native revocation, not a custom revoke.
    denied = any(e.get('stage') == 'DENY' and e.get('reason') == 'NATIVE_REVOKED'
                 for e in matching)
    reconciled = any(e.get('stage') == 'RECONCILE' and e.get('custom_revoked') is True
                     for e in matching)
    valid = all((native_state == 'REVOKED', custom_state == 'REVOKED',
                 fintech_not_found is True, has_two_catalogs is True, denied, reconciled))
    return {'result': 'PASS_OBSERVED' if valid else 'INCOMPLETE',
            'native_readback': native_state, 'custom_state': custom_state,
            'fintech_isolation': fintech_not_found, 'two_catalogs_verified': has_two_catalogs,
            'native_caused_denial': denied, 'reconciliation_transition': reconciled,
            'ordered_events': stages}


def replay_verdict(first_http, first_token, second_http, second_token, second_error):
    """Do not treat a 200 on an identical JWT assertion replay as safe."""
    allowed_errors = {'invalid_grant', 'invalid_request', 'access_denied'}
    passed = (first_http == 200 and first_token is True and
              second_http in (400, 401, 403) and not second_token and
              second_error in allowed_errors)
    return {'result': 'PASS_OBSERVED' if passed else 'FAIL_OR_INCOMPLETE',
            'first_issued': first_http == 200 and first_token,
            'replay_rejected': second_http in (400,401,403) and
                               not second_token and second_error in allowed_errors,
            'first_http': first_http, 'second_http': second_http,
            'second_error': second_error if second_error in allowed_errors else 'OTHER'}


def tenant_issuer_match(verified_claims, expected_issuer):
    return (isinstance(verified_claims, Mapping) and
            verified_claims.get('iss') == expected_issuer and
            isinstance(verified_claims.get('sub'), str) and bool(verified_claims['sub']))


def seller_policy(member, action):
    if action not in ('view-dashboard', 'change-payout-account'):
        return {'decision': 'DENY', 'reason': 'UNKNOWN_ACTION'}
    permitted = bool(member and member.get('active') and
        (action == 'view-dashboard' or
         (member.get('role_name') == 'OWNER' and
          member.get('is_legal_representative') is True)))
    return {'decision':'ALLOW' if permitted else 'DENY',
            'reason':'ROLE_AND_REPRESENTATION' if permitted else 'ROLE_OR_REPRESENTATION_DENIED'}
