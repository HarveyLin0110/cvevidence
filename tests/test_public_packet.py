from cvevidence_core.public_packet import compact

def test_huge_fixture_lines_omitted_without_mutating_saved_snapshot():
    long='a'*2000
    original={'sources':[{'source_id':'P-test','text':'diff --git a/x.py b/x.py\n'+long+'\n+if len(value)>2048: reject()'}]}
    packet=compact(original)
    assert long not in packet['sources'][0]['text'] and '+if len' in packet['sources'][0]['text']
    assert original['sources'][0]['text'].count(long)==1
    assert packet['sources'][0]['omitted_lines']==1
