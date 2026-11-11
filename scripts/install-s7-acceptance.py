#!/usr/bin/env python3
"""Safety-checked additive Magalu Section 7 dashboard installer.

Usage: python3 /tmp/s7/scripts/install-s7-acceptance.py --check
       python3 /tmp/s7/scripts/install-s7-acceptance.py
"""
import argparse
import ast
from datetime import datetime,timezone
import os
from pathlib import Path
import shutil
import subprocess
import sys

EXPECTED=Path('/Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc')
BUNDLE=Path(__file__).resolve().parents[1]
ADD_FILES=[
'demo/s7_policy.py','demo/s7_assurance.py','demo/s7_acceptance.py',
'demo/static/m3_section7.css','demo/static/m3_section7.js',
'demo/templates/m3_section7.html','docs/M3_SECTION7_DEMO_ACCEPTANCE.md',
'scripts/run-s7-acceptance.sh','scripts/configure-s7-provider.py',
 'tests/test_s7_acceptance.py']

def replace_once(text,old,new,description):
    if new in text:return text
    if text.count(old)!=1:
        raise ValueError('Cannot safely apply '+description+'; expected anchor count 1, observed '+str(text.count(old)))
    return text.replace(old,new,1)

def changes_main(src):
    return replace_once(src,
        'app.include_router(_m3_native_lab_router)',
        'app.include_router(_m3_native_lab_router)\n'
        '# RFP Section 7.2 acceptance cockpit — additive, no API mock.\n'
        'from demo.s7_acceptance import router as _s7_acceptance_router\n'
        'app.include_router(_s7_acceptance_router)',
        'register S7 router')

def _augment_verified_principal(source):
    """Add *names-only* verified-token metadata irrespective of dict formatting.

    Unlike the v1 installer, find the real assignment using Python's parser instead
    of requiring one exact whitespace-sensitive literal. Never replace existing
    fields or rewrite the application's authentication and consent code.
    """
    module=ast.parse(source)
    callbacks=[n for n in module.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))
               and n.name=='callback']
    if len(callbacks)!=1:
        raise ValueError('Cannot safely locate exactly one OIDC callback')
    assignments=[n for n in ast.walk(callbacks[0]) if isinstance(n,ast.Assign)
                 and any(isinstance(t,ast.Name) and t.id=='newprincipal' for t in n.targets)]
    if len(assignments)!=1 or not isinstance(assignments[0].value,ast.Dict):
        raise ValueError('Cannot safely locate the newprincipal OIDC dictionary')
    assignment=assignments[0]
    existing={k.value for k in assignment.value.keys
              if isinstance(k,ast.Constant) and isinstance(k.value,str)}
    for n in ast.walk(callbacks[0]):
        if (isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
            and n.func.attr=='update' and isinstance(n.func.value,ast.Name)
            and n.func.value.id=='newprincipal' and n.args and isinstance(n.args[0],ast.Dict)):
            existing.update(k.value for k in n.args[0].keys
                            if isinstance(k,ast.Constant) and isinstance(k.value,str))
    fields={
        'id_token_claim_names':'sorted(str(k) for k in claims.keys())',
        'userinfo_claim_names':'userinfo_keys',
        'userinfo_observed':'userinfo_observed',
        'token_fingerprint':"hashlib.sha256(tokens['id_token'].encode()).hexdigest()[:20]",
        'verified_id_token':'True',
    }
    missing=[(k,v) for k,v in fields.items() if k not in existing]
    if not missing:return source
    indent=' '*assignment.col_offset
    additions=indent+'newprincipal.update({\n'
    additions+=''.join(indent+f'    {k!r}: {v},\n' for k,v in missing)
    additions+=indent+'})\n'
    lines=source.splitlines(keepends=True)
    lines.insert(assignment.end_lineno,additions)
    output=''.join(lines)
    ast.parse(output)  # fail safe before returning modified content
    return output

def changes_storefront(s):
    s=replace_once(s,"        display='Cliente autenticado'\n",
        "        display='Cliente autenticado'\n"
        "        userinfo_keys=[]\n        userinfo_observed=False\n",
        'capture UserInfo metadata')
    s=replace_once(s,
        "                    if user.get('sub')==claims['sub']:\n",
        "                    if user.get('sub')==claims['sub']:\n"
        "                        userinfo_keys=sorted(str(k) for k in user.keys())\n"
        "                        userinfo_observed=True\n",
        'collect verified matching UserInfo claim names')
    s=_augment_verified_principal(s)
    s=replace_once(s,
        "        if pending['purpose']=='approval':\n",
        "        if pending['purpose']=='s7_stepup':\n"
        "            old=s.get('principal')\n"
        "            if not old or old['sub']!=newprincipal['sub'] or old['issuer']!=newprincipal['issuer']:\n"
        "                return view(request,error='Section 7: identidade alterada durante step-up.',code=403)\n"
        "            fresh=claims.get('auth_time')\n"
        "            if (claims.get('acr')!=ACR_TOTP or\n"
        "                'totp' not in [str(v).lower() for v in claims.get('amr',[]) if isinstance(v,str)] or\n"
        "                not isinstance(fresh,(int,float)) or fresh<pending['iat']-30):\n"
        "                return view(request,error='Section 7: WSO2 TOTP/AAL2 não comprovado.',code=403)\n"
        "            s['principal']=newprincipal\n"
        "            s['s7_stepup_tx']=pending['request_id']\n"
        "            return redirect('http://localhost:8180/m3/section7?tx='+pending['request_id'])\n"
        "        if pending['purpose']=='approval':\n",
        'add WSO2 TOTP challenge tied to transaction')
    s=replace_once(s,
        "    if purpose=='approval':\n        params['acr_values']=ACR_TOTP",
        "    if purpose in ('approval','s7_stepup'):\n        params['acr_values']=ACR_TOTP",
        'ensure S7 challenge actually requests the WSO2 TOTP ACR')
    if "@app.get('/api/s7/evidence')" not in s:
        s+='''\n\n# RFP S7: never returns tokens or raw user attributes; only live session metadata.
@app.get('/api/s7/evidence')
def s7_evidence(request:Request):
    p=active(request).get('principal')
    if not p or p.get('verified_id_token') is not True:
        return JSONResponse({'authenticated':False},status_code=401)
    return JSONResponse({
        'authenticated':True,'brand':BRAND,'channel':CHANNEL,
        'tenant':manifest()['clients'][CLIENT_KEY]['tenant_domain'],
        'sub':p['sub'],'issuer':p['issuer'],
        'client_id':p['client_id'],'verified_id_token':True,
        'token_fingerprint':p.get('token_fingerprint'),
        'id_token_claim_names':p.get('id_token_claim_names',[]),
        'userinfo_claim_names':p.get('userinfo_claim_names',[]),
        'userinfo_observed':p.get('userinfo_observed',False),
        'acr':p.get('acr'),'amr':p.get('amr',[]),
        'auth_time':p.get('auth_time'),'s7_stepup_tx':active(request).get('s7_stepup_tx')
    },headers={'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'})

@app.get('/s7/stepup')
def s7_stepup(request:Request,tx:str=''):
    import uuid as _uuid
    if BRAND!='magalupay' or CHANNEL!='web':
        raise HTTPException(404,'This challenge is only for MagaluPay Web')
    try:
        if str(_uuid.UUID(tx))!=tx:raise ValueError('invalid tx')
    except ValueError:
        raise HTTPException(400,'Invalid transaction identifier') from None
    s=active(request)
    if not s.get('principal'):
        raise HTTPException(401,'Authenticate in MagaluPay Web before starting the challenge')
    client=manifest()['clients'][CLIENT_KEY]
    return authorize(s,client,discovery(client['tenant_domain']),'s7_stepup',tx)
'''
    return s

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--check',action='store_true');args=ap.parse_args()
    here=Path.cwd().resolve()
    top=subprocess.check_output(['git','rev-parse','--show-toplevel'],text=True).strip()
    if here!=EXPECTED or Path(top).resolve()!=EXPECTED:
        raise SystemExit('FATAL: Wrong git root. Expected '+str(EXPECTED)+'; actual '+str(top))
    updates={}
    for path,method in [('demo/main.py',changes_main),('demo/storefront.py',changes_storefront)]:
        old=(EXPECTED/path).read_text()
        new=method(old)
        if old!=new:updates[path]=new
    # Navigation discoverability: a single new entry in the existing main lab sidebar.
    navpath='demo/templates/base.html'
    nav=(EXPECTED/navpath).read_text()
    newnav=replace_once(nav,'<a href="/pairwise"',
       '<a href="/m3/section7">▦ &nbsp; Section 7 · Acceptance Studio</a>\n'
       '<a href="/pairwise"','add Section 7 navigation link')
    if newnav!=nav:updates[navpath]=newnav
    for path in ADD_FILES:
        source=BUNDLE/path
        if not source.is_file():raise SystemExit('Missing bundle file: '+str(source))
        target=EXPECTED/path
        if target.exists():
            if target.read_bytes()!=source.read_bytes():
                raise SystemExit('Refusing to overwrite existing file with different contents: '+path)
        else:updates[path]=source.read_bytes()
    print('Project root verified:',EXPECTED)
    print('Files to create/update:')
    for f in sorted(updates):print(' -',f)
    if args.check:
        print('CHECK OK. No project files modified.')
        return
    backup=EXPECTED/'generated'/'backups'/('s7-acceptance-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    backup.mkdir(parents=True,exist_ok=True)
    os.chmod(backup,0o700)
    for path in updates:
        original=EXPECTED/path
        if original.exists():
            dst=backup/path;dst.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(original,dst)
            os.chmod(dst,0o600)
    written=[]
    try:
        for path,body in updates.items():
            dst=EXPECTED/path;dst.parent.mkdir(parents=True,exist_ok=True)
            temp=dst.with_suffix(dst.suffix+'.s7new')
            if isinstance(body,str):temp.write_text(body)
            else:temp.write_bytes(body)
            os.replace(temp,dst)
            written.append(path)
        pyfiles=['demo/main.py','demo/storefront.py']+[p for p in ADD_FILES if p.endswith('.py')]
        subprocess.run([sys.executable,'-m','py_compile',*pyfiles],check=True)
        subprocess.run(['git','diff','--check'],check=True)
    except Exception:
        for path in reversed(written):
            b=backup/path
            if b.exists():shutil.copy2(b,EXPECTED/path)
            else:(EXPECTED/path).unlink(missing_ok=True)
        raise
    print('INSTALLED: additive Section 7 evidence cockpit; backup:',backup)
    print('WSO2/DB not modified. No external provider provisioned.')

if __name__=='__main__':main()
