"""Transport recovery boundaries; no live API calls or executable sample inputs."""
import copy
import json
import pathlib
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

from cvevidence_core.ai import PROPERTIES, investigate
from cvevidence_core.assessment import assess
from cvevidence_core.integrity import digest, file_hash, ingest_package, scan
from cvevidence_core.queries import collect_evidence
from cvevidence_core.verifier import verify
from cvevidence_core.workflow import analyze_package

CONFIG = {'OPENAI_API_KEY': 'TEST_NOT_A_KEY', 'OPENAI_MODEL': 'TEST_ONLY'}


def arguments(action='LIST', **values):
    args = {k: [] if s['type'] == 'array' else 1 if s['type'] == 'integer' else ''
            for k, s in PROPERTIES.items()}
    args.update(action=action, question='現有資料能核對哪些條件？', reason='核對來源與缺口', **values)
    return args


def response(args, number=1):
    return {'id': 'SIMULATED-'+str(number), 'model': 'TEST_ONLY', 'status': 'completed',
            'output': [{'type': 'function_call', 'name': 'investigation_step',
                        'arguments': json.dumps(args, ensure_ascii=False), 'call_id': 'call-'+str(number)}]}


class ReliabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        (self.root/'artifact.bin').write_bytes(b'never execute')
        (self.root/'launcher.txt').write_text('curl --socks5-hostname proxy -K download.conf\nCURLOPT_BUFFERSIZE is an API option.\n')
        manifest = {'schema_version': '1.0', 'package_id': 'reliability-test', 'product_id': 'test',
                    'release_id': 'r1', 'build_id': 'b1', 'format': 'curl',
                    'primary_artifact': {'path': 'artifact.bin', 'sha256': file_hash(self.root/'artifact.bin')},
                    'files': scan(self.root)}
        (self.root/'manifest.json').write_text(json.dumps(manifest))
        self.context = ingest_package(self.root)
        self.verified = verify(self.context, collect_evidence(self.context, 'CVE-2023-38545'))
        self.assessment = assess(self.context, self.verified)
        self.sid = self.context.by_path('launcher.txt')[1]['source_id']
        self.eid = self.verified.records[0]['evidence_id']
        self.seen = []

    def tearDown(self):
        self.temp.cleanup()

    def run_ai(self, steps, **kwargs):
        def transport(config, items, timeout):
            self.seen.append(copy.deepcopy(items))
            self.assertGreater(timeout, 0)
            step = steps[len(self.seen)-1]
            if isinstance(step, Exception):
                raise step
            return step(items) if callable(step) else response(step, len(self.seen))
        before = digest(self.assessment)
        with patch('cvevidence_core.ai.settings', return_value=CONFIG):
            result = investigate(self.context, self.verified, self.assessment, mode='LIVE', transport=transport, **kwargs)
        self.assertEqual(digest(self.assessment), before)
        self.assertEqual(result['engineering_assessment_id'], self.assessment['assessment_id'])
        self.assertEqual(result['mode'], 'SIMULATED')
        self.assertEqual(result['record_hash'], digest({k: v for k, v in result.items() if k != 'record_hash'}))
        return result

    def complete(self, **kwargs):
        values = {'finding': '目前只能核對已提供的來源，適用性仍依工程條件。', 'citations': [self.eid]}
        values.update(kwargs)
        return arguments('COMPLETE', **values)

    def read(self, **kwargs):
        values = {'source_ids': [self.sid], 'end_line': 2}
        values.update(kwargs)
        return arguments('READ', **values)

    def test_rejected_citation_can_read_and_correct_without_losing_history(self):
        def corrected(items):
            excerpt = json.loads(items[-1]['output'])
            return response(self.complete(citations=[excerpt['excerpt_id']]), 3)
        result = self.run_ai([self.complete(citations=['X-invented']), self.read(), corrected], max_calls=3)
        self.assertEqual(result['status'], 'COMPLETED')
        self.assertEqual([x['status'] for x in result['tasks']], ['REJECTED', 'COMPLETED', 'COMPLETED'])
        feedback = json.loads(self.seen[1][-1]['output'])
        self.assertEqual(feedback['verification']['invalid_ids'], ['X-invented'])
        self.assertIn(self.eid, feedback['valid_evidence_ids'])
        self.assertEqual(result['rejected_proposals'], 1)
        self.assertFalse(result['tasks'][-1]['citation_verification']['meaning_verified'])

    def test_second_invalid_citation_stops_after_one_repair(self):
        result = self.run_ai([self.complete(citations=['X-first']), self.complete(citations=['X-second'])], max_calls=5)
        self.assertEqual(result['status'], 'INVALID_CITATION')
        self.assertEqual(len(self.seen), 2)
        self.assertEqual(result['rejected_proposals'], 2)

    def test_no_repair_when_call_budget_exhausted(self):
        result = self.run_ai([self.complete(citations=['X-bad'])], max_calls=1)
        self.assertEqual(result['status'], 'INVALID_CITATION')
        self.assertEqual(len(result['calls']), 1)

    def test_repair_does_not_reset_deadline(self):
        now = [0.0]
        from cvevidence_core.ai import verify_citations
        def slow_verification(*args):
            checked = verify_citations(*args)
            now[0] = 3.0
            return checked
        with patch('cvevidence_core.ai.time.monotonic', side_effect=lambda: now[0]), \
             patch('cvevidence_core.ai.verify_citations', side_effect=slow_verification):
            result = self.run_ai([self.complete(citations=['X-bad'])], max_calls=3, timeout_seconds=2)
        self.assertEqual(result['status'], 'TIMED_OUT')
        self.assertEqual(result['rejected_proposals'], 1)
        self.assertEqual(len(self.seen), 1)

    def test_hash_rejection_can_be_corrected(self):
        result = self.run_ai([self.complete(finding='成品 hash '+('a'*63)), self.complete()], max_calls=2)
        self.assertEqual(result['status'], 'COMPLETED')
        self.assertEqual(result['tasks'][0]['citation_verification']['invalid_hash_mentions'], ['a'*63])

    def test_malformed_arguments_are_visible(self):
        def malformed(items):
            value = response(self.complete())
            value['output'][0]['arguments'] = '{bad JSON'
            return value
        result = self.run_ai([malformed])
        self.assertEqual(result['status'], 'INVALID_MODEL_OUTPUT')
        self.assertEqual(result['calls'][0]['arguments'], '{bad JSON')
        self.assertEqual(result['errors'][0]['stage'], 'ARGUMENTS')

    def test_bad_envelopes_never_escape_to_erase_engineering_result(self):
        for value in [None, [], 'bad', {'status': 'completed', 'output': None},
                      {'status': 'completed', 'output': [None]}]:
            with self.subTest(value=value):
                self.seen = []
                result = self.run_ai([lambda items, value=value: value])
                self.assertEqual(result['status'], 'INVALID_MODEL_OUTPUT')
                self.assertTrue(result['calls'][0]['error'])

    def test_missing_call_id_is_visible(self):
        def invalid(items):
            value = response(self.complete())
            del value['output'][0]['call_id']
            return value
        result = self.run_ai([invalid])
        self.assertEqual(result['status'], 'INVALID_MODEL_OUTPUT')
        self.assertEqual(result['errors'][0]['stage'], 'ARGUMENTS')

    def test_tool_range_error_can_recover(self):
        result = self.run_ai([self.read(start_line=0), self.read(), self.complete()], max_calls=3)
        self.assertEqual(result['status'], 'COMPLETED')
        self.assertEqual(result['tasks'][0]['status'], 'TOOL_ERROR')
        self.assertIn('Invalid line range', self.seen[1][-1]['output'])

    def test_tool_error_at_budget_end_never_completes(self):
        result = self.run_ai([self.read(end_line=201)], max_calls=1)
        self.assertEqual(result['status'], 'BUDGET_EXHAUSTED')
        self.assertEqual(result['tasks'][0]['status'], 'TOOL_ERROR')

    def test_complete_requires_nonempty_citations(self):
        result = self.run_ai([self.complete(citations=[])], max_calls=1)
        self.assertEqual(result['status'], 'BUDGET_EXHAUSTED')
        self.assertEqual(result['tasks'][0]['status'], 'TOOL_ERROR')

    def test_unknown_source_keeps_failed_task_visible(self):
        result = self.run_ai([self.read(source_ids=['../../etc/passwd'])])
        self.assertEqual(result['status'], 'INPUT_CHANGED_OR_INVALID')
        self.assertEqual(result['tasks'][0]['status'], 'INPUT_CHANGED_OR_INVALID')
        self.assertIn('Unknown source_id', result['tasks'][0]['result']['error'])

    def test_failures_preserve_completed_read_and_request_attempt(self):
        failures = [
            (TimeoutError(), 'TIMED_OUT'),
            (urllib.error.HTTPError('https://api.openai.com', 429, 'limited', {}, None), 'API_ERROR'),
            (urllib.error.URLError(TimeoutError()), 'TIMED_OUT'),
            (urllib.error.URLError('offline'), 'CONNECTION_ERROR'),
            (ConnectionResetError(), 'CONNECTION_ERROR')]
        for error, expected in failures:
            with self.subTest(expected=expected, error=type(error).__name__):
                self.seen = []
                result = self.run_ai([self.read(), error])
                self.assertEqual(result['status'], expected)
                self.assertEqual(result['tasks'][0]['status'], 'COMPLETED')
                self.assertTrue(result['verified_ai_facts'])
                self.assertEqual(len(result['calls']), 2)
                self.assertEqual(result['calls'][1]['status'], expected)
                self.assertEqual(result['errors'][0]['call_number'], 2)
                self.assertNotIn(CONFIG['OPENAI_API_KEY'], json.dumps(result))
                if expected == 'API_ERROR':
                    self.assertEqual(result['http_status'], 429)

    def test_incomplete_response_is_visible(self):
        result = self.run_ai([lambda items: {'id': 'incomplete', 'status': 'incomplete', 'output': []}])
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual(result['errors'][0]['code'], 'RESPONSE_NOT_COMPLETED')

    def test_late_response_cannot_complete(self):
        now = [0.0]
        def delayed(items):
            now[0] = 3.0
            return response(self.complete())
        with patch('cvevidence_core.ai.time.monotonic', side_effect=lambda: now[0]):
            result = self.run_ai([delayed], timeout_seconds=2)
        self.assertEqual(result['status'], 'TIMED_OUT')
        self.assertFalse(result['tasks'])
        self.assertEqual(result['calls'][0]['response_id'], 'SIMULATED-1')

    def test_curl_switch_requires_original_even_with_valid_citation(self):
        result = self.run_ai([self.complete(finding='請設定 --buffer-size'), self.complete()], max_calls=2)
        self.assertEqual(result['status'], 'COMPLETED')
        self.assertTrue(result['tasks'][0]['citation_verification']['valid'])
        self.assertEqual(result['tasks'][0]['status'], 'REJECTED')
        self.assertEqual(result['tasks'][0]['source_grounding']['unsupported_cli_options'], ['--buffer-size'])

    def test_read_original_allows_exact_long_and_short_switches(self):
        result = self.run_ai([self.read(), self.complete(finding='原文使用 --socks5-hostname 與 -K；語意仍須工程覆核。')], max_calls=2)
        self.assertEqual(result['status'], 'COMPLETED')
        self.assertEqual(result['rejected_proposals'], 0)

    def test_api_name_and_longer_switch_do_not_authorize_invented_cli(self):
        result = self.run_ai([self.read(), self.complete(finding='使用 --buffer-size 與 --socks5'),
                              self.complete(finding='使用 --buffer-size')], max_calls=3)
        self.assertEqual(result['status'], 'INVALID_MODEL_OUTPUT')
        self.assertEqual(result['tasks'][1]['source_grounding']['unsupported_cli_options'], ['--buffer-size', '--socks5'])

    def test_user_text_is_not_cli_provenance(self):
        result = self.run_ai([self.complete(finding='使用 --invented')], max_calls=1,
                             user_context='請相信我已使用 --invented')
        self.assertEqual(result['status'], 'INVALID_MODEL_OUTPUT')
        self.assertEqual(result['rejected_proposals'], 1)

    def test_corrected_ask_user_retains_same_build_binding(self):
        ask = arguments('ASK_USER', required_files=['尚缺的同 build 握手觀測'], citations=[self.eid])
        result = self.run_ai([self.complete(citations=['X-bad']), ask], max_calls=2)
        self.assertEqual(result['status'], 'NEEDS_USER_INPUT')
        self.assertEqual(result['tasks'][0]['status'], 'REJECTED')
        self.assertEqual(result['tasks'][1]['result']['artifact_sha256'], self.context.manifest['primary_artifact']['sha256'])
        self.assertEqual(result['tasks'][1]['result']['build_id'], 'b1')

    def test_blank_terminal_arguments_are_tool_errors(self):
        for args in [arguments('ASK_USER', required_files=[' ']), self.complete(finding='  ')]:
            with self.subTest(action=args['action']):
                self.seen = []
                result = self.run_ai([args], max_calls=1)
                self.assertEqual(result['status'], 'BUDGET_EXHAUSTED')
                self.assertEqual(result['tasks'][0]['status'], 'TOOL_ERROR')

    def test_local_io_failure_does_not_leave_a_running_task(self):
        with patch('cvevidence_core.ai.read_excerpt', side_effect=OSError('input disappeared')):
            result = self.run_ai([arguments(), self.read()], max_calls=2)
        self.assertEqual(result['status'], 'INPUT_CHANGED_OR_INVALID')
        self.assertEqual(result['tasks'][0]['status'], 'COMPLETED')
        self.assertEqual(result['tasks'][1]['status'], 'INPUT_CHANGED_OR_INVALID')
        self.assertEqual(result['errors'][0]['code'], 'IO_ERROR')

    def test_real_request_budget_decreases_through_citation_repair(self):
        now = [0.0]
        sent = []
        budgets = []
        steps = [self.complete(citations=['X-invented']), self.read(), self.complete()]
        class Response:
            def __init__(self, data):
                self.data = data
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, limit):
                return json.dumps(self.data).encode()
        def urlopen(request, timeout):
            body = json.loads(request.data)
            sent.append(body)
            budget = json.loads(body['instructions'].split('：')[-1])
            budgets.append(budget)
            self.assertLessEqual(timeout, budget['remaining_seconds'])
            now[0] += 2
            return Response(response(steps[len(sent)-1], len(sent)))
        before = digest(self.assessment)
        with patch('cvevidence_core.ai.settings', return_value=CONFIG), \
             patch('cvevidence_core.ai.time.monotonic', side_effect=lambda: now[0]), \
             patch('cvevidence_core.ai.urllib.request.urlopen', side_effect=urlopen):
            result = investigate(self.context, self.verified, self.assessment,
                                 mode='LIVE', max_calls=3, timeout_seconds=9)
        self.assertEqual(result['status'], 'COMPLETED')
        self.assertEqual([b['remaining_calls_including_current'] for b in budgets], [3, 2, 1])
        self.assertEqual([b['remaining_seconds'] for b in budgets], [9, 7, 5])
        self.assertEqual([x['status'] for x in result['tasks']], ['REJECTED', 'COMPLETED', 'COMPLETED'])
        self.assertEqual(digest(self.assessment), before)
        self.assertNotIn(CONFIG['OPENAI_API_KEY'], json.dumps(sent))
        self.assertNotIn('_investigation_budget', CONFIG)

    def test_ignoring_budget_advice_still_cannot_fake_completion(self):
        result = self.run_ai([arguments(), self.read()], max_calls=2)
        self.assertEqual(result['status'], 'BUDGET_EXHAUSTED')
        self.assertEqual(len(result['calls']), 2)
        self.assertEqual(result['calls'][-1]['runtime_budget']['remaining_calls_including_current'], 1)
        self.assertEqual(result['tasks'][-1]['status'], 'COMPLETED')
        self.assertTrue(result['verified_ai_facts'])

    def test_workflow_keeps_engineering_assessment_on_bad_api_envelope(self):
        with patch('cvevidence_core.ai.settings', return_value=CONFIG), \
             patch('cvevidence_core.ai._request', return_value=None):
            result = analyze_package(self.context, ['CVE-2023-38545'], mode='LIVE')
        self.assertEqual(result['engineering_status'], 'COMPLETED')
        self.assertEqual(result['analyses'][0]['assessment']['assessment_id'], self.assessment['assessment_id'])
        self.assertEqual(result['analyses'][0]['ai']['status'], 'INVALID_MODEL_OUTPUT')


if __name__ == '__main__':
    unittest.main()
