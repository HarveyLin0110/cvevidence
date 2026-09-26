from copy import deepcopy
import pytest
from cvevidence_core.evidence_requests import validate
from tests.test_condition_plan import conditions

def request():
    return {'condition_id':'C3','material':'當次生效設定','why':'確認功能是否開啟','owner':'部署工程師',
        'how':'匯出當次服務設定','alternative':'同次啟動設定紀錄','search_terms':['runtime.conf'],
        'existing_source_ids':[],'insufficiency':'現有原碼不能證明生效設定','expected_resolution':'確認此條件是否滿足'}

def test_small_single_gap_request():
    rows=conditions(); rows[2]['state']='USER_MATERIAL_MISSING'
    assert validate([request()],rows,generic=True)[0]['priority']==1

@pytest.mark.parametrize('case',['many','multiple','duplicate','capability','exclusion','no_how'])
def test_reject_broad_unnecessary_or_unactionable_requests(case):
    rows=conditions(); rows[2]['state']='USER_MATERIAL_MISSING'; req=[request()]
    if case=='many':req=req*4
    if case=='multiple':req.append(dict(request(),condition_id='C2'))
    if case=='duplicate':req.append(deepcopy(req[0]))
    if case=='capability':rows[2]['state']='CAPABILITY_GAP'
    if case=='exclusion':rows[0]['state']='OBSERVED_EXCLUSION'
    if case=='no_how':req[0]['how']=''
    with pytest.raises(ValueError):validate(req,rows,generic=True)
