"""Focused depth checks with simulated transport, not real CVE verification."""
import json
from unittest.mock import patch

from .test_general_triage import context, public_record, analyzed
from cvevidence_core.ai import investigate, PROPERTIES, _request
from cvevidence_core.queries import collect_evidence
from cvevidence_core.verifier import verify
from cvevidence_core.integrity import digest


def test_pc_review_cannot_stop_with_only_a_missing_file(context):
    entry = analyzed(context)['analyses'][0]
    verified = verify(context, collect_evidence(context, entry['cve_id']))
    original = digest(entry['assessment'])
    seen=[]
    def transport(config, items, timeout):
        seen.append(items.copy())
        args={k: [] if spec['type']=='array' else 1 if spec['type']=='integer' else '' for k,spec in PROPERTIES.items()}
        args.update(action='ASK_USER',question='TEST_ONLY：產品是否為公告目標？',reason='TEST_ONLY 核對範圍',
                    required_files=['請產品維護者提供同成品型號與版本映射。'],citations=[verified.records[0]['evidence_id']])
        if len(seen)==2:
            args['finding']='PC1：僅盤點清單，元件尚未確認。\nPC2：尚未完成實作及綁定分析。\nPC3：尚未完成部署分析；先確認產品範圍。'
        return {'id':'SIMULATED','model':'TEST_ONLY','status':'completed','output':[
            {'type':'function_call','name':'investigation_step','call_id':str(len(seen)),
             'arguments':json.dumps(args)}]}
    with patch('cvevidence_core.ai.settings',return_value={'OPENAI_API_KEY':'TEST_ONLY','OPENAI_MODEL':'TEST_ONLY'}):
        result=investigate(context,verified,entry['assessment'],mode='LIVE',transport=transport,
                           analysis_depth='pc',max_calls=2,public_record=public_record())
    assert result['mode']=='SIMULATED' and result['status']=='NEEDS_USER_INPUT'
    assert result['tasks'][0]['status']=='TOOL_ERROR'
    assert result['tasks'][1]['status']=='COMPLETED'
    assert digest(entry['assessment'])==original
    assert entry['assessment']['cve_condition_verification_status']=='NOT_RUN'
    assert all(c['state']=='UNKNOWN' for c in entry['assessment']['conditions'])
    packet=json.loads(seen[0][0]['content'])
    assert packet['pc_evidence_packet'] and packet['condition_groups']['cve_id']==entry['cve_id']
    assert all(not p['excerpts'] for p in packet['pc_evidence_packet'])  # inventory is not source content


def test_depth_request_preserves_high_and_reserves_reasoning_output():
    captured=[]
    class Reply:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def read(self,*args):return b'{"status":"completed"}'
    def send(request,timeout):
        captured.append(json.loads(request.data));return Reply()
    with patch('urllib.request.urlopen',side_effect=send):
        _request({'OPENAI_API_KEY':'TEST_ONLY','OPENAI_MODEL':'gpt-5.6-sol',
                  'OPENAI_REASONING_EFFORT':'high','_analysis_depth':'pc'},[],10)
    assert captured[0]['reasoning']['effort']=='high'
    assert captured[0]['max_output_tokens']==9000
    assert 'PC1、PC2、PC3 三段' in captured[0]['instructions']
    assert captured[0]['store'] is False


def test_depth_summary_is_visible_without_expanding_tool_log():
    from streamlit.testing.v1 import AppTest
    ai={'context_hash':'scope','cve_id':'CVE-2024-1179','engineering_assessment_id':'A-test',
        'mode':'SIMULATED','status':'NEEDS_USER_INPUT','analysis_depth':'PC_EVIDENCE_REVIEW',
        'tasks':[{'action':'ASK_USER','status':'COMPLETED','finding':'PC1 元件待確認；PC2 實作待確認；PC3 運作待確認。'}]}
    app=AppTest.from_string('import streamlit as st\nfrom cvevidence.analysis_view import render_ai\n'
        'render_ai(st,'+repr(ai)+',context_hash="scope",cve_id="CVE-2024-1179",assessment_id="A-test")').run(timeout=15)
    assert not app.exception
    assert any(x.value=='PC1／PC2／PC3 查核說明' for x in app.subheader)
    assert any('PC1 元件待確認' in x.value for x in app.text)
