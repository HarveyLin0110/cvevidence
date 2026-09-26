from copy import deepcopy
import pytest
from tests.test_general_triage import context
from tests.test_condition_plan import conditions
from cvevidence_core.condition_plan import record
from cvevidence_core.condition_review import dossier,verify_review
from cvevidence_core.sources import read_excerpt

def test_review_rechecks_bytes_and_does_not_promote_verdict(context):
    x=read_excerpt(context,context.by_path('source/main.c')[1]['source_id'])
    rows=conditions();rows[1].update(citations=[x['excerpt_id']],state='OBSERVED_SUPPORT')
    ai={'context_hash':context.context_hash,'cve_id':'CVE-2024-1179','condition_plan':record(context,'CVE-2024-1179',rows),'excerpts':[x]}
    d=dossier(context,ai)
    decision={'dossier_hash':d['dossier_hash'],'reviewer':'TEST_ONLY','conditions':[{'condition_id':r['condition_id'],'relation':'SUPPORTED' if i==1 else 'UNRESOLVED','rationale':'逐字核對測試'} for i,r in enumerate(rows)]}
    receipt=verify_review(context,d,decision)
    assert receipt['formal_verdict_unchanged'] and not receipt['reviewer_authenticated']
    bad=deepcopy(decision);bad['conditions'][0]['relation']='EXCLUDED'
    with pytest.raises(ValueError):verify_review(context,d,bad)
    bad=deepcopy(d);bad['conditions'][1]['evidence'][0]['text']='forged'
    with pytest.raises(ValueError):verify_review(context,bad,decision)
