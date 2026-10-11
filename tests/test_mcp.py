import io
import json
import os
import pickle
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modelguard import mcp


class Evil:
    def __reduce__(self):
        return (os.system, ('echo no',))


def rpc(*messages):
    """Run the stdio server over the given messages and return the parsed responses."""
    stdin = io.StringIO(''.join((m if isinstance(m, str) else json.dumps(m)) + '\n' for m in messages))
    stdout = io.StringIO()
    with patch.object(mcp, '_lower_priority'):
        mcp.serve(stdin, stdout)
    return [json.loads(line) for line in stdout.getvalue().splitlines()]


class McpTests(unittest.TestCase):
    def test_handshake_and_tool_list(self):
        init, tools = rpc(
            {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-06-18'}},
            {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
            {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'})
        self.assertEqual(init['result']['protocolVersion'], '2025-06-18')
        self.assertIn('tools', init['result']['capabilities'])
        names = {t['name'] for t in tools['result']['tools']}
        self.assertEqual(names, {'modelguard_scan', 'modelguard_hub', 'modelguard_verify'})
        self.assertTrue(all(t['annotations']['readOnlyHint'] for t in tools['result']['tools']))

    def test_unknown_protocol_version_gets_latest(self):
        (init,) = rpc({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '1999-01-01'}})
        self.assertEqual(init['result']['protocolVersion'], mcp.PROTOCOL_VERSIONS[0])

    def test_scan_tool_reports_high(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'model.pkl').write_bytes(pickle.dumps(Evil()))
            (resp,) = rpc({'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
                           'params': {'name': 'modelguard_scan', 'arguments': {'path': tmp}}})
        result = resp['result']
        self.assertFalse(result['isError'])
        self.assertEqual(result['structuredContent']['summary']['findings_high'], 1)
        self.assertIn('[HIGH] MG006', result['content'][0]['text'])
        self.assertNotIn('files', result['structuredContent'])

    def test_tool_errors_and_protocol_errors(self):
        responses = rpc(
            {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': 'modelguard_scan',
                                                                          'arguments': {'path': '/does/not/exist'}}},
            {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'nope', 'arguments': {}}},
            {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {'name': 'modelguard_scan', 'arguments': {}}},
            'not json',
            {'jsonrpc': '2.0', 'id': 4, 'method': 'unknown/method'},
            {'jsonrpc': '2.0', 'id': 5, 'method': 'ping'})
        by_id = {r.get('id'): r for r in responses}
        self.assertTrue(by_id[1]['result']['isError'])
        self.assertEqual(by_id[2]['error']['code'], -32602)
        self.assertTrue(by_id[3]['result']['isError'])
        self.assertEqual(by_id[None]['error']['code'], -32700)
        self.assertEqual(by_id[4]['error']['code'], -32601)
        self.assertEqual(by_id[5]['result'], {})

    def test_findings_truncated_for_context(self):
        report = {'scanner_version': 'x', 'target': 't', 'status': 'insufficient_evidence', 'coverage': {},
                  'summary': {}, 'limitations': [], 'files': [],
                  'findings': [{'rule': 'MG001', 'severity': 'review', 'file': str(i), 'message': 'm'}
                               for i in range(mcp.MAX_FINDINGS + 5)]}
        compact = mcp._compact(report, False)
        self.assertEqual(len(compact['findings']), mcp.MAX_FINDINGS)
        self.assertEqual(compact['findings_truncated'], 5)


if __name__ == '__main__':
    unittest.main()
