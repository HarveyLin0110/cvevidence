"""Small model-step contract; evidence tools and verdicts remain in the core."""
from copy import deepcopy
from dataclasses import dataclass
import json
import re
import socket
import urllib.error
import urllib.request

MAX_PROVIDER_INPUT_BYTES = 1024 * 1024
MAX_PROVIDER_RECEIPT_BYTES = 64 * 1024


@dataclass(frozen=True)
class ProviderStep:
    decision: dict
    receipt: dict


class ProviderError(Exception):
    """Only finite statuses and safe codes cross the provider boundary."""
    def __init__(self, status: str, code: str):
        allowed = {'TIMED_OUT', 'API_ERROR', 'CONNECTION_ERROR', 'INCOMPLETE',
                   'BUDGET_EXHAUSTED', 'CONFIG_REQUIRED', 'INVALID_MODEL_OUTPUT', 'FAILED', 'INPUT_CHANGED_OR_INVALID'}
        self.status = status if status in allowed else 'FAILED'
        self.code = code if isinstance(code, str) and re.fullmatch(r'[A-Z][A-Z0-9_]{0,99}', code) else 'PROVIDER_ERROR'
        super().__init__(self.code)


def responses_request(config, items, timeout, *, instructions, tool, max_output_tokens):
    """The existing bounded HTTP exchange, shared by legacy and v2 callers."""
    body = {'model': config['OPENAI_MODEL'], 'instructions': instructions,
            'input': items, 'tools': [tool], 'tool_choice': 'required',
            'parallel_tool_calls': False, 'max_output_tokens': max_output_tokens, 'store': False}
    if config['OPENAI_MODEL'].startswith(('gpt-5', 'gpt-6', 'o3', 'o4')):
        body['reasoning'] = {'effort': config.get('OPENAI_REASONING_EFFORT', 'medium')}
        body['include'] = ['reasoning.encrypted_content']
    request = urllib.request.Request('https://api.openai.com/v1/responses',
        data=json.dumps(body, ensure_ascii=False, allow_nan=False).encode(),
        headers={'Authorization': 'Bearer ' + config['OPENAI_API_KEY'], 'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(2_000_001)
        if len(data) > 2_000_000:
            raise ValueError('API_RESPONSE_TOO_LARGE')
        return json.loads(data)


class OpenAIAdapter:
    provider_id = 'openai_api'
    auth_type = 'api_key'
    version = '1.0'

    def __init__(self, config: dict, *, transport=None):
        self._config = {key: config[key] for key in
                        ('OPENAI_API_KEY', 'OPENAI_MODEL', 'OPENAI_REASONING_EFFORT') if key in config}
        self.model = self._config.get('OPENAI_MODEL')
        self.reasoning_effort = self._config.get('OPENAI_REASONING_EFFORT', 'medium')
        self.mode = 'SIMULATED' if transport is not None else 'LIVE'
        self._transport = transport
        self._items = []
        self._packet = None
        self._history = []
        self._pending = None
        self._closed = False

    def step(self, *, instructions: str, packet: dict, history: list[dict], budget: dict, timeout: float) -> ProviderStep:
        from .ai import TOOL
        if self._closed:
            raise ProviderError('FAILED', 'PROVIDER_ALREADY_CLOSED')
        if not self._config.get('OPENAI_API_KEY') or not self.model:
            raise ProviderError('CONFIG_REQUIRED', 'OPENAI_CONFIGURATION_REQUIRED')
        if timeout <= 0:
            raise ProviderError('TIMED_OUT', 'REQUEST_TIMEOUT')
        if self._packet is None:
            if history:
                raise ProviderError('FAILED', 'PROVIDER_HISTORY_MISMATCH')
            self._packet = deepcopy(packet)
            self._items = [{'role': 'user', 'content': json.dumps(packet, ensure_ascii=False, allow_nan=False)}]
        elif packet != self._packet or not self._pending or len(history) != len(self._history) + 1:
            raise ProviderError('FAILED', 'PROVIDER_HISTORY_MISMATCH')
        else:
            if history[:-1] != self._history or history[-1].get('decision') != self._pending['decision']:
                raise ProviderError('FAILED', 'PROVIDER_HISTORY_MISMATCH')
            self._items.extend(self._pending['output'])
            self._items.append({'type': 'function_call_output', 'call_id': self._pending['call_id'],
                               'output': json.dumps(history[-1]['result'], ensure_ascii=False, allow_nan=False)})
            self._history = deepcopy(history)
        config = {**self._config, '_investigation_budget': budget,
                  '_analysis_depth': 'pc' if 'pc_evidence_packet' in packet else 'focused'}
        # Native reasoning/tool items are private state, but still consume the
        # same request-size allowance as the normalized packet/history.
        if len(json.dumps(self._items, ensure_ascii=False, allow_nan=False).encode()) > MAX_PROVIDER_INPUT_BYTES:
            raise ProviderError('BUDGET_EXHAUSTED', 'PROVIDER_INPUT_LIMIT')
        try:
            if self._transport is not None:
                response = self._transport(config, deepcopy(self._items), timeout)
            else:
                response = responses_request(config, self._items, timeout, instructions=instructions,
                    tool=TOOL, max_output_tokens=9000 if config['_analysis_depth'] == 'pc' else 3000)
        except (socket.timeout, TimeoutError):
            raise ProviderError('TIMED_OUT', 'REQUEST_TIMEOUT') from None
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise ProviderError('CONFIG_REQUIRED', 'PROVIDER_AUTHENTICATION_FAILED') from None
            if exc.code == 429:
                raise ProviderError('FAILED', 'PROVIDER_RATE_OR_QUOTA_LIMIT') from None
            raise ProviderError('API_ERROR', 'PROVIDER_HTTP_ERROR') from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                raise ProviderError('TIMED_OUT', 'REQUEST_TIMEOUT') from None
            raise ProviderError('CONNECTION_ERROR', 'PROVIDER_CONNECTION_FAILED') from None
        except OSError:
            raise ProviderError('CONNECTION_ERROR', 'PROVIDER_CONNECTION_FAILED') from None
        except (ValueError, TypeError, KeyError):
            raise ProviderError('INVALID_MODEL_OUTPUT', 'INVALID_PROVIDER_RESPONSE') from None
        if not isinstance(response, dict):
            raise ProviderError('INVALID_MODEL_OUTPUT', 'INVALID_PROVIDER_RESPONSE')
        receipt = {'provider': self.provider_id, 'response_id': response.get('id'),
                   'status': response.get('status'), 'model': response.get('model'), 'usage': response.get('usage')}
        if response.get('status') != 'completed':
            return ProviderStep({}, receipt)
        try:
            if not isinstance(receipt['response_id'], str) or not receipt['response_id']:
                raise ValueError('Missing response ID')
            output = response['output']
            if not isinstance(output, list) or any(not isinstance(item, dict) for item in output):
                raise ValueError('Invalid response output')
            calls = [item for item in output if item.get('type') == 'function_call']
            if len(calls) != 1 or calls[0].get('name') != 'investigation_step':
                raise ValueError('Expected one investigation step')
            call = calls[0]
            if not isinstance(call.get('call_id'), str) or not call['call_id'] or not isinstance(call.get('arguments'), str):
                raise ValueError('Invalid function call')
            decision = json.loads(call['arguments'])
            if not isinstance(decision, dict):
                raise ValueError('Decision must be an object')
        except (ValueError, KeyError, TypeError):
            raise ProviderError('INVALID_MODEL_OUTPUT', 'INVALID_PROVIDER_RESPONSE') from None
        self._pending = {'decision': deepcopy(decision), 'output': deepcopy(output), 'call_id': call['call_id']}
        return ProviderStep(decision, receipt)

    def close(self):
        self._items.clear()
        self._history.clear()
        self._packet = None
        self._pending = None
        self._config.clear()
        self._closed = True
