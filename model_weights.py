#!/usr/bin/env python3
"""Nonce-prefixed full-weight hashing. Python 3.11+, standard library only.

The local collector has no network calls. The reference collector streams public
Hugging Face files at an immutable revision, without writing weights to disk.
This module neither obtains nor cryptographically verifies hardware quotes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import struct
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

SCHEMA = "confidential-ai/model-challenge/v1"
MANIFEST_SCHEMA = "confidential-ai/hf-weight-manifest/v1"
RESULT_SCHEMA = "confidential-ai/model-weight-result/v1"
SCOPE = "all-safetensors-v1"
HASH_DOMAIN = b"confidential-ai/model-weight-challenge/v1\0"
REPORT_DOMAIN = b"confidential-ai/model-cvm-report/v1\0"
CHUNK = 1024 * 1024
MAX_METADATA = 20 * 1024 * 1024
MAX_FILES = 10000
MAX_BYTES = 1024 ** 4
HEX = re.compile(r"^[0-9a-f]+$")
REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$")


def canonical(value) -> bytes:
    """Protocol JSON: ASCII-escaped, sorted keys, compact; no floats in identities."""
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("Duplicate JSON key: " + key)
        out[key] = value
    return out


def parse_json(data):
    return json.loads(data, object_pairs_hook=_pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))


def read_json(path):
    with Path(path).open('rb') as stream:
        data = stream.read(MAX_METADATA + 1)
    if len(data) > MAX_METADATA:
        raise ValueError("JSON exceeds size limit")
    return parse_json(data)


def write_json(path, value):
    """Never overwrite an existing evidence/result file."""
    with Path(path).open("xb") as f:
        f.write(canonical(value) + b"\n")


def checked_hex(value, size):
    if not isinstance(value, str) or len(value) != size * 2 or not HEX.fullmatch(value):
        raise ValueError("Expected lowercase hex for %d bytes" % size)
    return bytes.fromhex(value)


def validate_request(request):
    fields = {"schema", "request_id", "nonce_client", "model_id", "revision",
              "scope", "model_verification_required"}
    if not isinstance(request, dict) or set(request) != fields:
        raise ValueError("Invalid challenge fields")
    if request["schema"] != SCHEMA or request["scope"] != SCOPE:
        raise ValueError("Unsupported challenge protocol/scope")
    if request["model_verification_required"] is not True:
        raise ValueError("This protocol requires explicit model verification")
    checked_hex(request["nonce_client"], 32)
    checked_hex(request["request_id"], 16)
    checked_hex(request["revision"], 20)
    if not isinstance(request["model_id"], str) or not REPO.fullmatch(request["model_id"]):
        raise ValueError("Expected HF organization/repository")
    return request


def make_request(model_id, revision, nonce, request_id):
    return validate_request({"schema": SCHEMA, "request_id": request_id,
                             "nonce_client": nonce, "model_id": model_id,
                             "revision": revision, "scope": SCOPE,
                             "model_verification_required": True})


def valid_path(name):
    if not isinstance(name, str) or not name or not name.isascii():
        raise ValueError("Only nonempty ASCII artifact paths are supported")
    parts = name.split("/")
    if any(p in ("", ".", "..") for p in parts) or "\\" in name or "\0" in name:
        raise ValueError("Unsafe artifact path")
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise ValueError("Control character in artifact path")
    return name


def validate_manifest(manifest, request=None):
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema", "scope", "model_id", "revision", "files"
    }:
        raise ValueError("Invalid manifest fields")
    if manifest["schema"] != MANIFEST_SCHEMA or manifest["scope"] != SCOPE:
        raise ValueError("Invalid manifest protocol/scope")
    if not REPO.fullmatch(manifest["model_id"]):
        raise ValueError("Invalid manifest model")
    checked_hex(manifest["revision"], 20)
    if request is not None:
        validate_request(request)
        for key in ("model_id", "revision", "scope"):
            if manifest[key] != request[key]:
                raise ValueError("Challenge and manifest disagree: " + key)
    files = manifest["files"]
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise ValueError("Invalid number of files")
    names = []
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "size", "hf_digest", "hf_digest_algorithm"}:
            raise ValueError("Invalid file metadata")
        names.append(valid_path(item["path"]))
        if not item["path"].endswith(".safetensors"):
            raise ValueError("Scope covers safetensors files only")
        if type(item["size"]) is not int or not 0 < item["size"] <= MAX_BYTES:
            raise ValueError("Invalid file size")
        if item["hf_digest_algorithm"] not in ("sha256", "git-sha1"):
            raise ValueError("Unsupported HF file digest")
        checked_hex(item["hf_digest"], 32 if item["hf_digest_algorithm"] == "sha256" else 20)
    if names != sorted(set(names)):
        raise ValueError("Files must be unique and lexicographically sorted")
    if sum(f["size"] for f in files) > MAX_BYTES:
        raise ValueError("Weight set exceeds 1 TiB limit")
    return manifest


def _allowed_url(url):
    u = urllib.parse.urlsplit(url)
    host = u.hostname or ""
    if u.scheme != "https" or u.username or u.password or u.port not in (None, 443):
        raise ValueError("Only HTTPS Hugging Face URLs are allowed")
    if not (host == "huggingface.co" or host.endswith(".huggingface.co")
            or host == "hf.co" or host.endswith(".hf.co")):
        raise ValueError("Unexpected download host: " + host)


class _HFRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _allowed_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def hf_open(url):
    _allowed_url(url)
    opener = urllib.request.build_opener(_HFRedirect)
    req = urllib.request.Request(url, headers={"Accept-Encoding": "identity",
                                               "User-Agent": "model-weight-verifier/1"})
    # Public models only: no Hugging Face credential is read or forwarded.
    response = opener.open(req, timeout=120)
    _allowed_url(response.url)
    if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
        response.close()
        raise ValueError("Expected an uncompressed complete HTTP 200 response")
    return response


def fetch_manifest(model_id, revision):
    make_request(model_id, revision, "00" * 32, "00" * 16)
    url = "https://huggingface.co/api/models/%s/revision/%s?blobs=true" % (model_id, revision)
    with hf_open(url) as response:
        data = response.read(MAX_METADATA + 1)
    if len(data) > MAX_METADATA:
        raise ValueError("HF metadata exceeds limit")
    info = parse_json(data)
    if info.get("sha") != revision:
        raise ValueError("HF returned a different commit")
    siblings = info.get("siblings")
    if not isinstance(siblings, list):
        raise ValueError("HF response has no file list")
    files = []
    seen = set()
    for item in siblings:
        name = item.get("rfilename", "")
        if name in seen:
            raise ValueError("Duplicate HF path")
        seen.add(name)
        if not name.endswith(".safetensors"):
            continue
        lfs = item.get("lfs")
        if isinstance(lfs, dict):
            algorithm, digest = "sha256", lfs.get("sha256")
        else:
            algorithm, digest = "git-sha1", item.get("blobId")
        files.append({"path": name, "size": item.get("size"),
                      "hf_digest_algorithm": algorithm, "hf_digest": digest})
    return validate_manifest({"schema": MANIFEST_SCHEMA, "scope": SCOPE,
                              "model_id": model_id, "revision": revision,
                              "files": sorted(files, key=lambda f: f["path"])})


def initial_hasher(request, manifest):
    validate_manifest(manifest, request)
    # Nonce precedes all model-dependent data. Every weight byte is fed into this
    # hasher, not merely an existing file digest or manifest root.
    identity = canonical({"request": request, "manifest": manifest})
    return hashlib.sha256(HASH_DOMAIN + checked_hex(request["nonce_client"], 32)
                          + struct.pack(">Q", len(identity)) + identity)


def hash_stream(hasher, stream, size, hf_algorithm, hf_digest):
    # Independent raw file digest also detects a bad HF/CDN response.
    raw = hashlib.sha256() if hf_algorithm == "sha256" else hashlib.sha1(
        ("blob %d\0" % size).encode("ascii"))
    count = 0
    while True:
        chunk = stream.read(min(CHUNK, size - count + 1))
        if not chunk:
            break
        count += len(chunk)
        if count > size:
            raise ValueError("File is longer than its manifest entry")
        hasher.update(chunk)
        raw.update(chunk)
    if count != size:
        raise ValueError("File is shorter than its manifest entry")
    if raw.hexdigest() != hf_digest:
        raise ValueError("File content does not match HF digest")


def _signature(s):
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def safe_open(root_fd, name):
    """Traverse beneath the pinned directory FD; reject symlinks at every level."""
    parts = valid_path(name).split("/")
    fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        out = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    finally:
        os.close(fd)
    if not stat.S_ISREG(os.fstat(out).st_mode):
        os.close(out)
        raise ValueError("Weights must be regular files")
    return out


def collect(request, manifest, model_dir=None):
    validate_request(request)
    validate_manifest(manifest, request)
    hasher = initial_hasher(request, manifest)
    started_at = int(time.time())
    started = time.perf_counter()
    total = 0
    root_fd = None
    if model_dir is not None:
        root = Path(model_dir)
        if root.is_symlink():
            raise ValueError("Model directory must not be a symlink")
        root = root.resolve(strict=True)
        names = sorted(p.relative_to(root).as_posix() for p in root.rglob("*.safetensors"))
        if names != [f["path"] for f in manifest["files"]]:
            raise ValueError("Local safetensors set differs from the HF manifest")
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    metadata = {}
    try:
        for i, f in enumerate(manifest["files"], 1):
            if root_fd is not None:
                fd = safe_open(root_fd, f["path"])
                with os.fdopen(fd, "rb", buffering=0) as stream:
                    before = os.fstat(stream.fileno())
                    if before.st_size != f["size"]:
                        raise ValueError("Local file size mismatch")
                    hash_stream(hasher, stream, f["size"], f["hf_digest_algorithm"], f["hf_digest"])
                    if _signature(before) != _signature(os.fstat(stream.fileno())):
                        raise ValueError("File changed during hashing")
                    metadata[f["path"]] = _signature(before)
            else:
                url = "https://huggingface.co/%s/resolve/%s/%s" % (
                    request["model_id"], request["revision"], urllib.parse.quote(f["path"], safe="/"))
                with hf_open(url) as stream:
                    hash_stream(hasher, stream, f["size"], f["hf_digest_algorithm"], f["hf_digest"])
            total += f["size"]
            print(json.dumps({"file": i, "file_count": len(manifest["files"]),
                              "bytes_read": total, "elapsed_seconds": round(time.perf_counter() - started, 3)}),
                  file=sys.stderr, flush=True)
        if root_fd is not None:
            for name, signature in metadata.items():
                fd = safe_open(root_fd, name)
                try:
                    if _signature(os.fstat(fd)) != signature:
                        raise ValueError("File changed before scan completed")
                finally:
                    os.close(fd)
            if sorted(p.relative_to(root).as_posix() for p in root.rglob("*.safetensors")) != [f["path"] for f in manifest["files"]]:
                raise ValueError("Weight set changed during scan")
    finally:
        if root_fd is not None:
            os.close(root_fd)
    return {"schema": RESULT_SCHEMA, "request": request, "manifest": manifest,
            "manifest_sha256": hashlib.sha256(canonical(manifest)).hexdigest(),
            "digest_sha256": hasher.hexdigest(), "total_bytes": total,
            "file_count": len(manifest["files"]),
            "source": "local-filesystem" if model_dir is not None else "huggingface-stream",
            "started_at": started_at, "finished_at": int(time.time()),
            "elapsed_milliseconds": round((time.perf_counter() - started) * 1000)}


def validate_result(result, request):
    validate_request(request)
    keys = {"schema", "request", "manifest", "manifest_sha256", "digest_sha256",
            "total_bytes", "file_count", "source", "started_at", "finished_at", "elapsed_milliseconds"}
    if not isinstance(result, dict) or set(result) != keys or result["schema"] != RESULT_SCHEMA:
        raise ValueError("Invalid result schema")
    if result["request"] != request:
        raise ValueError("Result is for a different challenge")
    manifest = validate_manifest(result["manifest"], request)
    if result["manifest_sha256"] != hashlib.sha256(canonical(manifest)).hexdigest():
        raise ValueError("Manifest hash mismatch")
    checked_hex(result["digest_sha256"], 32)
    if type(result["total_bytes"]) is not int or result["total_bytes"] != sum(f["size"] for f in manifest["files"]):
        raise ValueError("Result byte count mismatch")
    if type(result["file_count"]) is not int or result["file_count"] != len(manifest["files"]):
        raise ValueError("Result file count mismatch")
    for key in ("started_at", "finished_at", "elapsed_milliseconds"):
        if type(result[key]) is not int or result[key] < 0:
            raise ValueError("Invalid timing metadata")
    if result["finished_at"] < result["started_at"]:
        raise ValueError("Invalid time order")
    if result["source"] not in ("local-filesystem", "huggingface-stream"):
        raise ValueError("Invalid result source")
    return result


def compare_results(node_result, reference_result, request):
    validate_result(node_result, request)
    validate_result(reference_result, request)
    if node_result["source"] != "local-filesystem":
        raise ValueError("Node result must be from the local collector")
    if reference_result["source"] != "huggingface-stream":
        raise ValueError("Reference was not produced by the HF stream collector")
    return (node_result["manifest"] == reference_result["manifest"]
            and node_result["digest_sha256"] == reference_result["digest_sha256"])


def report_binding(request, node_result, public_key_der, policy_sha256, supplementary_sha512):
    validate_result(node_result, request)
    if node_result["source"] != "local-filesystem":
        raise ValueError("Only a local collection result may be bound as node evidence")
    if not public_key_der or len(public_key_der) > 4096:
        raise ValueError("Invalid public key length; caller must also validate SPKI and algorithm")
    checked_hex(policy_sha256, 32)
    checked_hex(supplementary_sha512, 64)
    record = {"protocol_version": "model-cvm-v1", "request": request,
              "node_result_sha256": hashlib.sha256(canonical(node_result)).hexdigest(),
              "node_public_key_sha256": hashlib.sha256(public_key_der).hexdigest(),
              "policy_digest": policy_sha256,
              "supplementary_evidence_sha512": supplementary_sha512}
    return {"record": record,
            "report_data_hex": hashlib.sha512(REPORT_DOMAIN + canonical(record)).hexdigest()}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    manifest = sub.add_parser("manifest", help="Fetch small HF metadata only")
    manifest.add_argument("--model-id", required=True)
    manifest.add_argument("--revision", required=True)
    manifest.add_argument("--output", required=True)
    for name in ("request", "reference"):
        s = sub.add_parser(name)
        for field in ("model-id", "revision", "nonce", "request-id", "output"):
            s.add_argument("--" + field, required=True)
    local = sub.add_parser("collect", help="Hash existing local weights without network")
    for field in ("request", "manifest", "model-dir", "output"):
        local.add_argument("--" + field, required=True)
    bind = sub.add_parser("report-data", help="Prepare REPORTDATA; does not obtain a hardware quote")
    for field in ("request", "node-result", "public-key-der", "policy-sha256", "supplementary-sha512", "output"):
        bind.add_argument("--" + field, required=True)
    a = p.parse_args()
    if a.command == "manifest":
        result = fetch_manifest(a.model_id, a.revision)
    elif a.command in ("request", "reference"):
        request = make_request(a.model_id, a.revision, a.nonce, a.request_id)
        result = request if a.command == "request" else collect(request, fetch_manifest(a.model_id, a.revision))
    elif a.command == "collect":
        result = collect(read_json(a.request), read_json(a.manifest), a.model_dir)
    else:
        result = report_binding(read_json(a.request), read_json(a.node_result),
                                Path(a.public_key_der).read_bytes(), a.policy_sha256, a.supplementary_sha512)
    write_json(a.output, result)


if __name__ == "__main__":
    main()
