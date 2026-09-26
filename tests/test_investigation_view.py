from streamlit.testing.v1 import AppTest
from cvevidence.investigation_view import lines
from tests.test_condition_plan import conditions

def render(ai):
    import streamlit as st
    from cvevidence.investigation_view import render
    render(st,ai)

def test_ui_distinguishes_capability_unread_and_missing():
    rows=conditions()
    rows[1]['state']='CAPABILITY_GAP'; rows[2]['state']='USER_MATERIAL_MISSING'
    ai={'context_hash':'h','cve_id':'CVE-2099-0001','condition_plan':{'context_hash':'h','cve_id':'CVE-2099-0001','conditions':rows}}
    app=AppTest.from_function(render,args=(ai,)).run()
    assert not app.exception
    output='\n'.join(x.value for x in [*app.text,*app.info,*app.caption])
    assert '不要求使用者反覆補檔' in output and '不代表使用者缺件' in output
    assert 'AI 提案' in '\n'.join(lines(ai))
    ai['condition_plan']['context_hash']='other'
    assert lines(ai)==[]


def render_request(ai):
    import streamlit as st
    from cvevidence.investigation_view import render_requests
    render_requests(st,ai)


def test_minimal_request_visible_details_collapsed_and_failed_ask_hidden():
    from .test_evidence_requests import request
    row=dict(request(),priority=1)
    ai={'tasks':[{'action':'ASK_USER','status':'COMPLETED','evidence_requests':[row]},
                 {'action':'ASK_USER','status':'TOOL_ERROR','evidence_requests':[dict(row,material='不要顯示失敗補件')]}]}
    app=AppTest.from_function(render_request,args=(ai,)).run()
    assert not app.exception
    text='\n'.join(x.value for x in app.text)
    assert '1. 當次生效設定' in text and '取得方式：向部署工程師' in text
    assert '不要顯示失敗補件' not in text
    assert app.expander[0].proto.expanded is False
