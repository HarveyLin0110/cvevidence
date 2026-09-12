from streamlit.testing.v1 import AppTest
from cvevidence.workflow_navigation import availability, PAGES


def app_for(has_run=True, failed=False, engineering=False):
    return AppTest.from_string('''import streamlit as st
from cvevidence.workflow_navigation import sidebar_steps
sidebar_steps(st, has_run=''' + repr(has_run) + ", failed=" + repr(failed) + ", has_engineering=" + repr(engineering) + ")").run()


def test_empty_failed_and_engineering_gate():
    assert availability(has_run=False, failed=False, has_engineering=True) == (True, False, False, False, False)
    assert availability(has_run=True, failed=True, has_engineering=True) == (True, False, False, False, True)
    app = app_for()
    assert not app.exception
    assert app.sidebar.button[3].disabled
    assert not app.sidebar.button[4].disabled
    app.sidebar.button[2].click().run()
    assert app.session_state.step == PAGES[2]


def test_completed_navigation_and_stale_selection_recovery():
    app = app_for(engineering=True)
    app.sidebar.button[3].click().run()
    assert app.session_state.step == PAGES[3]
    app.session_state.step = "04 報告與後續行動"
    app.run()
    assert app.session_state.step == PAGES[4]
    app = app_for(has_run=False)
    app.session_state.step = PAGES[3]
    app.run()
    assert not app.exception and app.session_state.step == PAGES[0]
