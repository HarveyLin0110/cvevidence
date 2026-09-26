from tests.test_general_triage import context
from cvevidence_core.relevance import rank

def test_patch_path_ranked_with_explained_bounded_coverage(context):
    result=rank(context,'diff --git a/main.c b/main.c\n+ main()',scan_limit=1)
    assert result['sources'][0]['path']=='source/main.c'
    assert result['sources'][0]['relevance_reasons']
    assert result['scanned_files']<=1
    assert result['semantic_verification'] is False
