"""Synthetic UI regressions: report selection does not run a model."""
from streamlit.testing.v1 import AppTest


def report_app():
    from types import SimpleNamespace
    import streamlit as st
    from cvevidence.ai_workspace import report_ai_selector
    records = [
        {'request': {'ai_id': 'latest', 'created_at': '2026-09-26T12:00:00'}, 'status': 'TIMED_OUT'},
        {'request': {'ai_id': 'older', 'created_at': '2026-09-26T11:00:00'}, 'status': 'COMPLETED'},
    ]
    runner = SimpleNamespace(ai_history=lambda _: (records, []))
    report_ai_selector(st, runner, SimpleNamespace(run_id='test'))
    st.text('chosen:' + st.session_state['selected-ai-test'])


def test_direct_report_includes_latest_failure_instead_of_hiding_it():
    app = AppTest.from_function(report_app).run()
    assert not app.exception
    assert app.session_state['selected-ai-test'] == 'latest'
    assert 'TIMED_OUT' in app.selectbox[0].options[1]


def test_report_selection_can_exclude_ai_or_follow_ai_page_selection():
    app = AppTest.from_function(report_app).run()
    app.selectbox[0].select('').run()
    app.run()
    assert app.session_state['selected-ai-test'] == ''
    app.session_state['selected-ai-test'] = 'older'
    app.run()
    assert app.selectbox[0].value == 'older'
    assert not app.exception
