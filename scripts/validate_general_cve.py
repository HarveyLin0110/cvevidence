"""Real generic-CVE Runner/AI validation using a declared unrelated demo input."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from time import monotonic


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--live', action='store_true')
    parser.add_argument('--env-file', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / 'src'))
    from cvevidence.runner import Runner
    from cvevidence.storage import RunStore
    from cvevidence.analysis_report import export_analysis
    from cvevidence_core.ai import settings
    from cvevidence_core.public_cve import brief
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'started_at': datetime.now(timezone.utc).isoformat(), 'live_requested': args.live,
              'scope': '真實 CVE 公開資料與本機 Runner/AI 驗收。輸入是今日 CMake demo，不冒充 TP-Link 韌體；應追問目標產品對應，不得判安全。',
              'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
              'source_hashes': {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in (root / 'src').rglob('*.py')}, 'checks': {}}
    def save(): (output / 'summary.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    runner = Runner(RunStore(output / 'runtime'))
    cve = 'CVE-2024-1179'
    started = monotonic()
    intake = runner.start_file(root / 'demo-inputs/runtime-v2/pc3_cmake_static.tar.gz', cve=cve)
    run = runner.analyze_offline(intake.run_id)
    assert run.status == 'COMPLETED'
    saved = runner.read_engineering(run.run_id)
    parent_bytes = runner.store._run_path(run.run_id).read_bytes()
    entry = saved['analyses'][0]
    info = brief(entry['public_cve_record'])
    report.update(run_id=run.run_id, cve_id=cve, context_hash=saved['context_hash'],
                  assessment=entry['assessment'], public_record=info, query_plan=entry['query_plan'])
    report['checks'].update(public_record_published=info['status'] == 'PUBLISHED',
                           needs_investigation=entry['assessment']['verdict'] == 'NEEDS_INVESTIGATION',
                           no_verified_conditions=all(c['state'] == 'UNKNOWN' for c in entry['assessment']['conditions']),
                           five_planned_queries=len(entry['query_plan']['queries']) == 5)
    (output / 'engineering.json').write_text(json.dumps(saved, ensure_ascii=False, indent=2))
    (output / 'report.txt').write_text(export_analysis(saved, context_hash=saved['context_hash'], cve_id=cve, run_id=run.run_id))
    save()
    if args.live:
        config = settings(args.env_file)
        for key in ('OPENAI_API_KEY', 'OPENAI_MODEL', 'OPENAI_REASONING_EFFORT'):
            if config.get(key): os.environ[key] = config[key]
        os.environ['CVEVIDENCE_AI_ENABLED'] = '1'
        live = runner.investigate_ai(run.run_id, consent=True,
            user_context='請確認 CVE-2024-1179 是否適用目前提供的成品。若公告產品與工程包不一致，請先核對目標對應，勿因名稱不同判安全；根據現有資料提出具體查核或補件問題。', timeout=180)
        (output / 'ai-record.json').write_text(json.dumps(live, ensure_ascii=False, indent=2))
        report['ai_status'] = live['status']
        ai_entry = (live.get('result') or {}).get('analyses', [{}])[0]
        ai = ai_entry.get('ai', {})
        report['ai'] = {k: ai.get(k) for k in ('mode', 'status', 'model', 'elapsed_seconds', 'record_hash')}
        report['ai']['calls'] = len(ai.get('calls', []))
        report['ai']['tasks'] = [{k: t.get(k) for k in ('action', 'question', 'reason', 'finding', 'required_files', 'status')}
                                 for t in ai.get('tasks', [])]
        current = (ai_entry.get('investigation_verification') or {}).get('assessment', {})
        report['checks'].update(live_completed=live['status'] in {'NEEDS_USER_INPUT', 'COMPLETED'},
                               real_live_calls=ai.get('mode') == 'LIVE' and len(ai.get('calls', [])) > 0,
                               rereview_stays_unknown=current.get('verdict') == 'NEEDS_INVESTIGATION',
                               parent_unchanged=runner.store._run_path(run.run_id).read_bytes() == parent_bytes,
                               saved_result_unchanged=runner.read_engineering(run.run_id) == saved,
                               reload_preserved=Runner(RunStore(output / 'runtime')).read_ai(live['request']['ai_id']) == live)
        report['ai_id'] = live['request']['ai_id']
    report['elapsed_seconds'] = round(monotonic() - started, 3)
    save()
    print(json.dumps({'checks': report['checks'], 'ai': report.get('ai', {}),
                      'elapsed_seconds': report['elapsed_seconds']}, ensure_ascii=False))
    return 0 if all(report['checks'].values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
