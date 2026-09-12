"""Display-only synthetic cases: future Query IDs must not be hidden."""
from cvevidence.result_summary import query_summaries
from cvevidence.analysis_report import export_analysis
from tests.test_analysis_view import sample, app_for, displayed

def test_future_queries_render_with_saved_title_purpose_and_status():
    payload = sample()
    entry = payload['analyses'][0]
    marker = '<script>TEST_ONLY</script>'
    entry['queries'].append({'query_id':'Q_EXTRA_FUTURE', 'title':'新增查核',
        'description':marker, 'pc_layer':'PC3', 'status':'COMPLETED_WITH_GAPS',
        'missing':['TEST_ONLY missing capture'], 'evidence_ids':[]})
    summary = query_summaries(entry)
    assert len(summary) == 2 and summary[1]['label'] == '新增查核'
    assert summary[1]['description'] == marker
    app = app_for(payload)
    assert not app.exception and not app.markdown
    assert marker in displayed(app)
    assert any(e.label.startswith('Q_EXTRA_FUTURE') for e in app.expander)
    report = export_analysis(payload, context_hash='test-context', cve_id=entry['cve_id'], run_id='TEST_ONLY')
    assert 'Q_EXTRA_FUTURE' in report and marker in report
    entry['queries'].append(dict(entry['queries'][-1]))
    assert query_summaries(entry)[1]['state'] == '結果重複，需覆核'
    assert query_summaries(entry)[1]['label'] == 'Q_EXTRA_FUTURE'

def test_v2_descriptions_do_not_relabel_old_q5_records():
    from cvevidence.query_display import query_description
    assert '運作收據' in query_description({'query_id':'Q5_PATH','query_plan_version':'2.0'})
    assert '不套用新版語意' in query_description({'query_id':'Q5_PATH'})
