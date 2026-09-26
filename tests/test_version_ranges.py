from cvevidence_core.version_ranges import normalize,compare

def ranges(**kw):
    return normalize([{'vendor':'TEST_ONLY','product':'x','versions':[{'version':'1.0.0','lessThan':'2.0.0','status':'affected',**kw}]}])

def test_range_end_distro_backport_and_changes_unknown():
    assert compare('1.9.0',ranges())['status']=='MATCHES_DECLARED_AFFECTED_RANGE'
    assert compare('2.0.0',ranges())['status']=='VERSION_UNRESOLVED'
    assert compare('1.9.0-ubuntu1',ranges())['status']=='VERSION_UNRESOLVED'
    assert compare('1.9.0',ranges(changes=[{'at':'1.5.0','status':'unaffected'}]))['status']=='VERSION_UNRESOLVED'

def test_conflicting_statements_not_assumed_fixed():
    r=ranges()+ranges(status='unaffected')
    assert compare('1.9.0',r)['status']=='VERSION_STATEMENTS_CONFLICT'
