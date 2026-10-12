"""Account exports must not publish report bytes at Streamlit's media URL."""
import ast
import asyncio
import base64
import json
from pathlib import Path
import pytest
from starlette.requests import Request
from starlette.exceptions import HTTPException
from streamlit.testing.v1 import AppTest
from streamlit.runtime.memory_media_file_storage import _calculate_file_id
from streamlit.web.server.starlette.starlette_routes import create_media_routes

RAW = 'TEST_ONLY 私有報告\n<script>alert("untrusted")</script>\n'.encode()
FILENAME = '工程查核報告.json'


def page(identity='a'*64, *, filename=FILENAME, mime='application/json', raw=RAW, label='下載 TEST_ONLY 報告'):
    app = AppTest.from_string('''import streamlit as st
from streamlit.runtime import get_instance
from cvevidence.private_downloads import download_button
if st.session_state['mode'] != 'local':
    st.session_state['_account_principal'] = st.session_state['mode']
download_button(st, st.session_state['label'], st.session_state['raw'],
    file_name=st.session_state['filename'], mime=st.session_state['mime'])
st.session_state['test_storage'] = get_instance().media_file_mgr._storage
''')
    for key,value in dict(mode=identity,filename=filename,mime=mime,raw=raw,label=label).items():
        app.session_state[key]=value
    return app.run()


def media_response(app, *, raw=RAW, method='GET', headers=()):
    storage=app.session_state['test_storage']
    file_id=_calculate_file_id(raw,'application/json',FILENAME)+'.json'
    scope={'type':'http','method':method,'path':'/media/'+file_id,
           'path_params':{'file_id':file_id},'headers':headers,'query_string':b'',
           'server':('localhost',8507),'scheme':'http'}
    return asyncio.run(create_media_routes(storage,None)[0].endpoint(Request(scope)))


def test_native_media_is_not_an_account_authorization_boundary():
    # Real pinned-framework handler with no cookie or authenticated user.
    app=page('local');assert not app.exception
    response=media_response(app)
    assert response.status_code==200 and response.body==RAW


@pytest.mark.parametrize('method,headers',[
    ('GET',()),('HEAD',()),('GET',((b'range',b'bytes=0-15'),)),
    ('GET',((b'cookie',b'user=TEST_ONLY_OTHER_ACCOUNT'),)),
])
def test_account_report_is_absent_even_with_the_exact_native_media_id(method,headers):
    app=page();assert not app.exception and not app.error
    with pytest.raises(HTTPException) as error:media_response(app,method=method,headers=headers)
    assert error.value.status_code==404
    assert not app.get('download_button')
    proto=app.get('bidi_component')[0].proto
    data=json.loads(proto.json)
    assert base64.b64decode(data['content'])==RAW and data['filename']==FILENAME
    assert 'TEST_ONLY 私有報告' not in proto.js_content+proto.html_content+proto.css_content


def test_account_transition_does_not_reuse_component_or_previous_payload():
    app=page();old=app.get('bidi_component')[0].key
    other=b'TEST_ONLY SECOND ACCOUNT'
    app.session_state['mode']='b'*64;app.session_state['raw']=other;app.run()
    assert not app.exception
    component=app.get('bidi_component')[0]
    assert component.key!=old
    assert base64.b64decode(json.loads(component.proto.json)['content'])==other
    assert not app.session_state['test_storage']._files_by_id


@pytest.mark.parametrize('identity',[None,'bad','../other'])
def test_missing_or_invalid_account_never_falls_back_to_public_media(identity):
    app=page(identity)
    assert not app.exception and app.error
    assert not app.get('bidi_component') and not app.get('download_button')
    assert not app.session_state['test_storage']._files_by_id


@pytest.mark.parametrize('changes',[
    {'filename':'../private.json'}, {'mime':'text/html'}, {'raw':object()},
])
def test_invalid_export_input_does_not_publish_content(changes):
    app=page(**changes)
    assert not app.exception and app.error
    assert not app.get('bidi_component') and not app.session_state['test_storage']._files_by_id


def test_large_export_has_an_explicit_limit_without_public_fallback(monkeypatch):
    monkeypatch.setattr('cvevidence.private_downloads.MAX_INLINE_BYTES',4)
    app=page()
    assert not app.exception and app.error
    assert not app.get('bidi_component') and not app.session_state['test_storage']._files_by_id


def test_user_markup_stays_component_data_and_all_report_views_use_the_boundary():
    label='TEST_ONLY <img src=x onerror=alert(1)>'
    app=page(label=label);proto=app.get('bidi_component')[0].proto
    assert json.loads(proto.json)['label']==label
    assert label not in proto.js_content+proto.html_content+proto.css_content
    root=Path(__file__).resolve().parents[1]/'src/cvevidence'
    for path in root.glob('*.py'):
        if path.name=='private_downloads.py':continue
        tree=ast.parse(path.read_text())
        direct=[n for n in ast.walk(tree) if isinstance(n,ast.Call)
                and isinstance(n.func,ast.Attribute) and n.func.attr=='download_button']
        assert not direct, f'{path.name} bypasses account export boundary'
