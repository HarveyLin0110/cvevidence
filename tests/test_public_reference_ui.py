from streamlit.testing.v1 import AppTest


def test_public_reference_scope_and_unread_sources_are_visible():
    def page(ai):
        import streamlit as st
        from cvevidence.investigation_view import render
        render(st, ai)
    ai={'context_hash':'test','cve_id':'CVE-2022-48174',
        'condition_plan':{'context_hash':'test','cve_id':'CVE-2022-48174','conditions':[]},
        'public_sources':{'sources':[{'source_id':'P-test','url':'https://example.com/test',
            'raw_sha256':'test-only','text':'TEST_ONLY public excerpt',
            'reference_origins':[{'container':'ADP','provider':'TEST_ONLY'}],
            'publisher_scope':'DOWNSTREAM_DISTRIBUTION'}],
            'unsupported_references':['https://example.com/unsupported'],
            'unvisited_references':['https://example.com/unvisited'], 'references_truncated':True}}
    app=AppTest.from_function(page,args=(ai,)).run()
    assert not app.exception
    assert any('下游發行版' in row.value for row in app.info)
    assert any('ADP / TEST_ONLY' in row.value for row in app.caption)
    assert any('尚未支援：https://example.com/unsupported' in row.value for row in app.text)
    assert any('尚未讀取：https://example.com/unvisited' in row.value for row in app.text)
    assert any('清單有截短' in row.value for row in app.caption)
