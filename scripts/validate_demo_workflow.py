"""Real approved demo inputs; UI regression validation, never exposed in the website."""
import json
from pathlib import Path
from streamlit.testing.v1 import AppTest
from cvevidence.runner import Runner
from cvevidence.storage import RunStore

root = Path(__file__).resolve().parents[1]
import argparse
parser = argparse.ArgumentParser(description='Exercise the two real demo workflows without LIVE API calls.')
parser.add_argument('--store', required=True, help='Local acceptance store; new records are preserved')
store = Path(parser.parse_args().store).resolve()
initial_count = len(Runner(RunStore(store)).store.list_runs())
script = 'import streamlit as st\nfrom cvevidence.workspace import workspace\nworkspace(st,store_root=' + repr(str(store)) + ')'
app = AppTest.from_string(script).run(timeout=30)
def button(label):
    matches = [b for b in app.button if b.label == label]
    assert len(matches) == 1, label
    matches[0].click().run(timeout=60)
    assert not app.exception and not app.error, (label, list(app.exception), list(app.error))
def select(label, value):
    next(s for s in app.selectbox if s.label == label).set_value(value).run(timeout=30)
    assert not app.exception
catalog = next(s for s in app.selectbox if s.label == '選擇已取得的產品／建置／資料包')
idx = next(i for i, label in enumerate(catalog.options) if '04_cmake' in label)
catalog.set_value(idx).run()
next(t for t in app.text_input if t.label.startswith('CVE ID')).set_value('CVE-2022-37434, CVE-2099-9999').run()
button('匯入並建立查核')
request_id = app.session_state.selected_request
runner = Runner(RunStore(store))
request = runner.read_request(request_id)
first, second = request.runs
button('開啟所選 CVE')
button('03 分析進度與結果')
button('執行 Q1–Q5 與正式判定')
affected_id = app.session_state.selected_run
assert runner.read_engineering(affected_id)['analyses'][0]['assessment']['verdict'] == 'AFFECTED'
button('04 AI 查核與補件')
assert any('尚無' in str(t.value) or '未啟用' in str(t.value) for t in [*app.info, *app.caption, *app.text])
button('05 報告與後續行動')
assert any(affected_id in c.value for c in app.code)
select('此請求的 CVE 紀錄', second.run_id)
button('開啟所選 CVE')
assert app.session_state.selected_run == second.run_id
assert next(b for b in app.button if b.label == '04 AI 查核與補件').disabled
button('03 分析進度與結果')
button('執行 Q1–Q5 與正式判定')
unknown_id = app.session_state.selected_run
assert runner.read_engineering(unknown_id)['analyses'][0]['assessment'] is None
assert not any('受影響判定的支持條件' in t.value for t in app.text)
button('05 報告與後續行動')
assert any(unknown_id in c.value and affected_id not in c.value for c in app.code)
select('此請求的 CVE 紀錄', first.run_id)
button('開啟所選 CVE')
assert app.session_state.selected_run == affected_id  # regression: used to reopen intake
assert any('PC3' in t.value for t in app.text)
assert len(runner.store.list_runs()) == initial_count + 4  # switching did not run analysis again
button('01 產品與資料來源')
button('建立另一個請求')
catalog = next(s for s in app.selectbox if s.label == '選擇已取得的產品／建置／資料包')
catalog.set_value(next(i for i, label in enumerate(catalog.options) if '06_cmake' in label)).run()
next(t for t in app.text_input if t.label.startswith('CVE ID')).set_value('CVE-2022-37434').run()
button('匯入並建立查核')
supplement_request = app.session_state.selected_request
button('開啟所選 CVE')
button('03 分析進度與結果')
button('執行 Q1–Q5 與正式判定')
missing_id = app.session_state.selected_run
original = runner.read_engineering(missing_id)
assert original['analyses'][0]['assessment']['verdict'] == 'NEEDS_INVESTIGATION'
button('04 AI 查核與補件')
button('套用已取得的補件並建立新 run')
button('執行 Q1–Q5 與正式判定')
completed_id = app.session_state.selected_run
assert runner.read_engineering(completed_id)['analyses'][0]['assessment']['verdict'] == 'AFFECTED'
assert runner.read_engineering(missing_id) == original
button('05 報告與後續行動')
assert any('補件前後工程結果' == h.value for h in app.subheader)
select('請求歷史', request_id)
button('載入請求')
button('開啟所選 CVE')
assert app.session_state.selected_run == affected_id
select('請求歷史', supplement_request)
button('載入請求')
button('開啟所選 CVE')
assert app.session_state.selected_run == completed_id
assert not list((store / 'ai').glob('*.start.json')) if (store / 'ai').exists() else True
result = dict(request_id=request_id, affected_run=affected_id, unsupported_run=unknown_id,
              request_switch='PASS', report_scope='PASS', ai_gate='PASS', repeated_analysis=False,
              real_engineering=True, live_ai_calls=0, supplement_request=supplement_request,
              missing_run=missing_id, supplemented_result=completed_id, parent_unchanged=True,
              two_requests_switch='PASS', supplement_flow='PASS')
(store / 'acceptance.json').write_text(json.dumps(result, indent=2))
print(json.dumps(result, indent=2))
