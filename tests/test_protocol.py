import copy
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import model_weights as mw
import github_verifier as gv


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.request = mw.make_request('example/model', 'ab' * 20, '12' * 32, '34' * 16)
        self.payloads = {'a.safetensors': b'first weight bytes', 'sub/b.safetensors': b'second bytes'}
        self.manifest = {'schema': mw.MANIFEST_SCHEMA, 'scope': mw.SCOPE,
                         'model_id': self.request['model_id'], 'revision': self.request['revision'],
                         'files': [{'path': name, 'size': len(data), 'hf_digest_algorithm': 'sha256',
                                    'hf_digest': hashlib.sha256(data).hexdigest()}
                                   for name, data in sorted(self.payloads.items())]}
        for name, data in self.payloads.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

    def collect(self, request=None):
        with patch('sys.stderr', io.StringIO()):
            return mw.collect(request or self.request, self.manifest, self.root)

    def test_full_byte_transcript_and_remote_equivalence(self):
        identity = json.dumps({'request': self.request, 'manifest': self.manifest},
                              ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')
        transcript = (b'confidential-ai/model-weight-challenge/v1\0' + bytes.fromhex('12' * 32)
                      + struct.pack('>Q', len(identity)) + identity + b''.join(self.payloads.values()))
        local = self.collect()
        self.assertEqual(local['digest_sha256'], hashlib.sha256(transcript).hexdigest())
        with patch.object(mw, 'hf_open', side_effect=[io.BytesIO(v) for v in self.payloads.values()]), patch('sys.stderr', io.StringIO()):
            reference = mw.collect(self.request, self.manifest)
        self.assertTrue(mw.compare_results(local, reference, self.request))

    def test_nonce_change_rehashes_to_different_digest(self):
        changed = dict(self.request, nonce_client='56' * 32)
        self.assertNotEqual(self.collect()['digest_sha256'], self.collect(changed)['digest_sha256'])

    def test_tampered_file_rejected(self):
        (self.root / 'a.safetensors').write_bytes(b'x' * len(self.payloads['a.safetensors']))
        with self.assertRaisesRegex(ValueError, 'HF digest'):
            self.collect()

    def test_truncated_and_extended_files_rejected(self):
        for content in (b'x', b'x' * 100):
            with self.subTest(content=content):
                (self.root / 'a.safetensors').write_bytes(content)
                with self.assertRaisesRegex(ValueError, 'size mismatch'):
                    self.collect()

    def test_stream_length_enforced(self):
        for content in (b'a', b'abc'):
            with self.assertRaises(ValueError):
                mw.hash_stream(hashlib.sha256(), io.BytesIO(content), 2, 'sha256', hashlib.sha256(b'ab').hexdigest())

    def test_unlisted_weight_rejected(self):
        (self.root / 'extra.safetensors').write_bytes(b'x')
        with self.assertRaisesRegex(ValueError, 'set differs'):
            self.collect()

    def test_symlink_rejected(self):
        path = self.root / 'a.safetensors'
        path.unlink()
        path.symlink_to(self.root / 'sub/b.safetensors')
        with self.assertRaises(OSError):
            self.collect()

    def test_manifest_paths_order_revision_rejected(self):
        for change in ('path', 'order', 'revision'):
            manifest = copy.deepcopy(self.manifest)
            if change == 'path':
                manifest['files'][0]['path'] = '../a.safetensors'
            elif change == 'order':
                manifest['files'].reverse()
            else:
                manifest['revision'] = '00' * 20
            with self.subTest(change=change), self.assertRaises(ValueError):
                mw.validate_manifest(manifest, self.request)

    def test_no_silent_downgrade_or_duplicate_keys(self):
        with self.assertRaises(ValueError):
            mw.validate_request(dict(self.request, model_verification_required=False))
        with self.assertRaises(ValueError):
            mw.parse_json('{"nonce":1,"nonce":2}')

    def test_git_blob_digest(self):
        value = b'small file'
        digest = hashlib.sha1(b'blob 10\0' + value).hexdigest()
        mw.hash_stream(hashlib.sha256(), io.BytesIO(value), len(value), 'git-sha1', digest)

    def test_reportdata_binds_result_key_policy_and_hardware(self):
        result = self.collect()
        base = mw.report_binding(self.request, result, b'public-key-der', '11' * 32, '22' * 64)
        self.assertEqual(len(bytes.fromhex(base['report_data_hex'])), 64)
        for field, value in [('digest_sha256', '00' * 32), ('finished_at', result['finished_at'] + 1)]:
            changed = dict(result, **{field: value})
            self.assertNotEqual(base, mw.report_binding(self.request, changed, b'public-key-der', '11' * 32, '22' * 64))
        for key, policy, supplement in [(b'other-key', '11' * 32, '22' * 64),
                                        (b'public-key-der', '33' * 32, '22' * 64),
                                        (b'public-key-der', '11' * 32, '44' * 64)]:
            self.assertNotEqual(base, mw.report_binding(self.request, result, key, policy, supplement))

    def job(self):
        return {'schema': 'confidential-ai/model-reference-job/v1', 'request': self.request,
                'repository': 'example/verifier', 'ref': 'refs/heads/main',
                'approved_sha': 'cd' * 20, 'dispatched_at': 123, 'run_id': 456}

    def envelope(self, result):
        job = self.job()
        env = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': job['repository'],
               'GITHUB_WORKFLOW_REF': job['repository'] + '/' + gv.WORKFLOW + '@' + job['ref'],
               'GITHUB_WORKFLOW_SHA': job['approved_sha'], 'GITHUB_SHA': job['approved_sha'],
               'GITHUB_RUN_ID': '456', 'GITHUB_RUN_ATTEMPT': '1',
               'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': job['ref']}
        with patch.dict(os.environ, env):
            return gv.envelope(dict(result, source='huggingface-stream'))

    def test_signed_context_rejects_wrong_run_and_request(self):
        document = self.envelope(self.collect())
        gv.check_envelope(document, self.job())
        document['github']['GITHUB_RUN_ID'] = '999'
        with self.assertRaises(ValueError):
            gv.check_envelope(document, self.job())
        document = self.envelope(self.collect())
        document['result']['request'] = dict(self.request, nonce_client='78' * 32)
        with self.assertRaises(ValueError):
            gv.check_envelope(document, self.job())

    def test_run_rejects_rerun_or_unapproved_code(self):
        job = self.job()
        run = {'id': 456, 'head_sha': job['approved_sha'], 'event': 'workflow_dispatch',
               'display_title': 'model-weights-' + self.request['request_id'], 'path': gv.WORKFLOW,
               'run_attempt': 1, 'repository': {'full_name': job['repository']}}
        gv.check_run(run, job)
        for key, value in [('run_attempt', 2), ('head_sha', 'ef' * 20), ('event', 'pull_request')]:
            with self.assertRaises(ValueError):
                gv.check_run(dict(run, **{key: value}), job)

    def test_invalid_signature_stops_before_digest_comparison(self):
        result = self.collect()
        with patch.object(gv, 'gh', side_effect=RuntimeError('invalid signature')), patch.object(gv, 'compare_results') as compare:
            with self.assertRaises(RuntimeError):
                gv.verify_downloaded(self.job(), self.root, result)
            compare.assert_not_called()

    def test_archive_path_traversal_rejected(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('../result.json', '{}')
            archive.writestr('bundle.json', '{}')
        with self.assertRaises(ValueError):
            gv.unpack_artifact(buffer.getvalue(), self.root)

    def test_digest_mismatch_is_not_pass(self):
        result = self.collect()
        reference = dict(result, source='huggingface-stream', digest_sha256='00' * 32)
        self.assertFalse(mw.compare_results(result, reference, self.request))


if __name__ == '__main__':
    unittest.main()
