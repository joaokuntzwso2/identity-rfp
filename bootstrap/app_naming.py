"""WSO2-compatible, deterministic application naming for the Magalu CIAM PoC.

WSO2 7.3.18 enforces ``^[a-zA-Z0-9._-]+(?: [a-zA-Z0-9._-]+)*$``
on its application names. Use one naming convention across bootstrap and
third-root onboarding, so repeated runs match previously created clients.
"""
from __future__ import annotations

import re

APPLICATION_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+(?: [a-zA-Z0-9._-]+)*$')


def check_application_name(name: str) -> str:
    """Fail locally (before the management API call) for invalid names."""
    if not isinstance(name, str) or not APPLICATION_NAME_PATTERN.fullmatch(name):
        raise ValueError(
            f'Invalid WSO2 application name {name!r}: '
            'only letters, digits, periods, underscores, hyphens and '
            'single spaces between name segments are supported'
        )
    return name


def application_name(*segments: str) -> str:
    """Produce repeatable names; do not change this format after provisioning."""
    if not segments:
        raise ValueError('At least one application name segment is required')
    normalized = []
    for segment in segments:
        if not isinstance(segment, str) or not segment.strip():
            raise ValueError('Application name segments must be nonempty strings')
        segment = segment.strip().upper()
        if not APPLICATION_NAME_PATTERN.fullmatch(segment):
            raise ValueError(f'Invalid application name segment {segment!r}')
        normalized.append(segment)
    return check_application_name('MAGALU CIAM POC - ' + ' - '.join(normalized))
