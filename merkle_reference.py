#!/usr/bin/env python3
"""Independent HF raw-weight streaming reference for cc-attestation/1.

Keeps the legacy model_weights v2 workflow unchanged. No GPU/TDX claims.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
import struct
import time
import urllib.parse
from model_weights import (fetch_manifest, hf_open, checked_hex, hash_stream,
                           validate_manifest, write_json, read_json)

SCHEMA = 'confidential-ai/cc-merkle-reference/v1'
ALGORITHM = 'sha256-nonce-file-rfc9162-v1'


def encode(value):
    """CC-E1; golden interoperability vectors checked against cc_common.protocol."""
    def item(v):
        if v is None: return b'n'
        if type(v) is bool: return b't' if v else b'f'
        if type(v) is int: return b'i' + struct.pack('>q', v)
        if isinstance(v, str):
            raw = v.encode('utf-8'); return b's' + struct.pack('>I', len(raw)) + raw
        if isinstance(v, bytes): return b'b' + struct.pack('>I', len(v)) + v
        if isinstance(v, list): return b'l' + struct.pack('>I', len(v)) + b''.join(item(x) for x in v)
        if isinstance(v, dict) and all(isinstance(k, str) for k in v):
            keys = sorted(v, key=lambda k: k.encode('utf-8'))
            return b'd' + struct.pack('>I', len(keys)) + b''.join(item(k)+item(v[k]) for k in keys)
        raise ValueError('Unsupported CC-E1 value')
    return b'CC-E1\0' + item(value)


def manifest_for_cc(hf):
    validate_manifest(hf)
    if any(f['hf_digest_algorithm'] != 'sha256' for f in hf['files']):
        raise ValueError('cc manifest requires independently supplied raw SHA256 for every file')
    return {'model_id': hf['model_id'], 'revision': hf['revision'],
            'files': [{'path': f['path'], 'size': f['size'], 'sha256': f['hf_digest']} for f in hf['files']]}


def merkle_root(leaves):
    if not leaves: raise ValueError('Empty model is not allowed')
    if len(leaves) == 1: return leaves[0]
    split = 1 << ((len(leaves)-1).bit_length()-1)
    return hashlib.sha256(b'\x01' + merkle_root(leaves[:split]) + merkle_root(leaves[split:])).digest()


def compute(hf, nonce, *, workers=4, opener=hf_open):
    nonce = checked_hex(nonce, 32)
    if type(workers) is not int or not 1 <= workers <= 8: raise ValueError('Use 1..8 workers')
    manifest = manifest_for_cc(hf)
    def leaf(f):
        url = 'https://huggingface.co/%s/resolve/%s/%s' % (
            manifest['model_id'], manifest['revision'], urllib.parse.quote(f['path'], safe='/'))
        h = hashlib.sha256(b'\x00' + nonce)
        with opener(url) as stream:
            hash_stream(h, stream, f['size'], f['hf_digest_algorithm'], f['hf_digest'])
        return h.digest()
    # map preserves the approved manifest order even when files finish out of order.
    with ThreadPoolExecutor(max_workers=workers) as pool:
        leaves = list(pool.map(leaf, hf['files']))
    return {'manifest': manifest, 'manifest_sha256': hashlib.sha256(encode(manifest)).hexdigest(),
            'root': merkle_root(leaves).hex(), 'file_count': len(leaves),
            'total_bytes': sum(f['size'] for f in manifest['files'])}


def reference(model_id, revision, nonce, request_id, workers):
    checked_hex(request_id, 16); checked_hex(nonce, 32); checked_hex(revision, 20)
    start = int(time.time())
    # Fetch pinned HF metadata independently, never accept a node's expected root/manifest.
    result = compute(fetch_manifest(model_id, revision), nonce, workers=workers)
    return {'schema': SCHEMA, 'algorithm': ALGORITHM, 'request_id': request_id,
            'nonce': nonce, **result, 'source': 'huggingface-stream',
            'started_at': start, 'finished_at': int(time.time())}


def envelope(result):
    if result.get('schema') != SCHEMA or result.get('source') != 'huggingface-stream':
        raise ValueError('Unsupported result')
    if os.environ.get('GITHUB_ACTIONS') != 'true': raise ValueError('Requires GitHub Actions')
    keys = ('GITHUB_REPOSITORY', 'GITHUB_WORKFLOW_REF', 'GITHUB_WORKFLOW_SHA', 'GITHUB_SHA',
            'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_EVENT_NAME', 'GITHUB_REF')
    context = {k: os.environ[k] for k in keys}
    if context['GITHUB_EVENT_NAME'] != 'workflow_dispatch': raise ValueError('Expected manual dispatch')
    return {'schema': 'confidential-ai/github-cc-merkle-reference/v1', 'result': result, 'github': context}


def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest='command', required=True)
    r=sub.add_parser('reference')
    for name in ('model-id','revision','nonce','request-id','output'): r.add_argument('--'+name, required=True)
    r.add_argument('--workers',type=int,default=4)
    e=sub.add_parser('envelope');e.add_argument('--result',required=True);e.add_argument('--output',required=True)
    a=p.parse_args()
    result=(reference(a.model_id,a.revision,a.nonce,a.request_id,a.workers) if a.command=='reference'
            else envelope(read_json(a.result)))
    write_json(a.output,result)


if __name__=='__main__': main()
