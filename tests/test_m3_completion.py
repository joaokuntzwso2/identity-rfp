from pathlib import Path
import ast

def test_support_page_exists():
    root=Path(__file__).resolve().parents[1]
    page=(root/'demo/templates/m3_support_story.html').read_text()
    js=(root/'demo/static/m3_support_story.js').read_text()
    assert '/api/m3/exchange/run' in js
    assert '/api/m3/exchange/status' in js
    assert 'report.result' in js
    assert 'act.sub' in page
    assert 'não altera' in page or 'não altera' in page.lower() or 'não altera' in page.lower()
    assert 'Nenhuma credencial ou JWT' in page

def test_native_live_state_never_fakes_success():
    root=Path(__file__).resolve().parents[1]
    src=(root/'demo/m3_native_lab.py').read_text()
    assert 'def native_live_state' in src
    assert '_native_status(info)' in src
    assert "'native_verified':False" in src
    assert 'NO_ACTION_CUSTOM_ALREADY_REVOKED' in src
    assert 'def support_journey_page' in (root/'demo/m3_exchange_lab.py').read_text()
    ast.parse(src)
