#!/usr/bin/env python3
"""Non-destructive, fail-closed install of additive Section 7 closure cockpit.

This installer does not modify WSO2, DBs, tenant configs, or generated secrets.
"""
import argparse
import ast
from datetime import datetime, timezone
from pathlib import Path
import shutil
import sys

ROOT = Path('/Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc')
FILES = (
    'demo/poc_closure.py',
    'demo/poc_closure_core.py',
    'demo/templates/m3_completion.html',
    'demo/static/m3_completion.css',
    'demo/static/m3_completion.js',
    'scripts/install-poc-closure.py',
    'scripts/deploy-poc-closure.sh',
    'scripts/verify-poc-closure.sh',
    'scripts/prepare-poc-ldap.py',
    'scripts/start-poc-ldap.sh',
    'scripts/prepare-poc-jwt-assertion.py',
    'docs/SECTION7_CLOSURE_RUNBOOK.md',
    'tests/test_poc_closure_core.py',
)


def patch_main(src):
    callback = 'def callback(request:Request):'
    seller = "return redirect('/auth/start/seller/web')"
    router_marker = 'from demo.poc_closure import router as _poc_closure_router'
    if src.count(callback) != 1:
        raise ValueError('Expected exactly one legacy callback; stop without writing')
    if src.count(seller) != 1 and "return redirect('/m3/completion?tab=b2b')" not in src:
        raise ValueError('Expected retired seller route; stop without writing')
    if router_marker not in src:
        # The callback has an explicitly scoped interception; others retain prior behavior.
        src=src.replace(callback, callback + "\n    from demo.poc_closure import seller_callback as _poc_seller_callback\n    new_response=_poc_seller_callback(request)\n    if new_response is not None:\n        return new_response", 1)
        src=src.replace(seller,"return redirect('/m3/completion?tab=b2b')",1)
        src+='\n# Section 7 additive B2C/B2B/M2M acceptance cockpit.\n'+router_marker+'\napp.include_router(_poc_closure_router)\n'
    ast.parse(src, filename='demo/main.py')
    return src


def main():
    p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');args=p.parse_args()
    here=Path(__file__).resolve().parents[1]
    cwd=Path.cwd().resolve()
    if cwd!=ROOT or not (ROOT/'demo/main.py').is_file() or not (ROOT/'.git').exists():
        sys.exit('ERROR: must run in exact isolated project Git root')
    import subprocess
    git_root=subprocess.check_output(['git','rev-parse','--show-toplevel'],cwd=ROOT,text=True).strip()
    if git_root!=str(ROOT):sys.exit('ERROR: Git root mismatch')
    for rel in FILES:
        if not (here/rel).is_file():sys.exit('ERROR: missing bundle file: '+rel)
    original=(ROOT/'demo/main.py').read_text()
    patched=patch_main(original)
    print('Git root verified:',ROOT)
    print('Installer source:',here)
    print('Files: demo/main.py (in-place patch) +',len(FILES),'additive bundle files')
    if args.check:
        print('CHECK OK. Nothing written.');return
    # All source validation completes before any file is changed.
    for rel in FILES:
        if rel.endswith('.py'):ast.parse((here/rel).read_text(), filename=rel)
    backup=ROOT/'generated'/'backups'/('section7-closure-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    backup.mkdir(parents=True,exist_ok=True)
    for rel in ('demo/main.py',)+FILES:
        destination=ROOT/rel
        if destination.exists():
            target=backup/rel;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(destination,target)
    try:
        for rel in FILES:
            destination=ROOT/rel;destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(here/rel,destination)
        (ROOT/'demo/main.py').write_text(patched)
        for rel in ('scripts/deploy-poc-closure.sh','scripts/verify-poc-closure.sh','scripts/start-poc-ldap.sh'):
            (ROOT/rel).chmod(0o755)
    except Exception:
        # Roll back overwritten files to private snapshot, including demo/main.py.
        for rel in ('demo/main.py',)+FILES:
            snapshot=backup/rel
            if snapshot.is_file():shutil.copy2(snapshot,ROOT/rel)
            else:(ROOT/rel).unlink(missing_ok=True)
        raise
    print('INSTALLED. Private rollback snapshot:',backup)
    print('No WSO2/DB changes made. Run scripts/verify-poc-closure.sh next.')

if __name__=='__main__':main()
