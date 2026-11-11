"""Render LOCAL-only WSO2 config. Passwords never printed/logged."""
import os
from pathlib import Path

def main():
    mode=os.getenv('MAGALU_ENV_MODE','legacy')
    template=Path('docker/wso2/deployment.isolated.template.toml' if mode=='isolated' else 'docker/wso2/deployment.template.toml')
    result=template.read_text()
    for key in ('IS_ADMIN_PASSWORD','IS_DB_USER','IS_DB_PASSWORD'):
        if '${'+key+'}' not in result:
            continue
        value=os.environ.get(key,'')
        if not value or any(c in value for c in ('\\','"','\r','\n')):
            raise SystemExit(f'{key} is missing or contains unsupported TOML characters')
        result=result.replace('${'+key+'}',value)
    target=Path('generated/wso2/deployment.toml')
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(result)
    target.chmod(0o600)
    print('Rendered',target,'mode:',mode,'(secrets hidden)')

if __name__=='__main__':
    main()
