#!/usr/bin/env python3
"""Dispatch, resume, and verify a pinned GitHub reference calculation.

This is the reference-comparison component of a verifier, not a hardware verifier.
The caller must validate quote signatures, policy, nonce, software identity and
REPORTDATA binding BEFORE dispatching; this CLI never claims to have done that.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import subprocess
import sys
import time
import urllib.parse
import zipfile
from pathlib import Path

from model_weights import (MAX_METADATA, REPO, canonical, checked_hex, compare_results,
                           parse_json, read_json, validate_request, validate_result, write_json)

WORKFLOW = ".github/workflows/model-reference.yml"
API_VERSION = "2026-03-10"
ENVELOPE = "confidential-ai/github-model-reference/v1"


def gh(args, *, data=None, binary=False, timeout=180):
    command = ["gh", *args]
    completed = subprocess.run(command, input=canonical(data) if data is not None else None,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if completed.returncode:
        # Never echo command input, credentials, or full remote response bodies.
        raise RuntimeError("GitHub CLI failed: " + completed.stderr.decode("utf-8", "replace")[-1600:])
    return completed.stdout if binary else completed.stdout.decode("utf-8")


def api(path, *, method="GET", data=None, binary=False):
    args = ["api", "--hostname", "github.com", "--method", method,
            "-H", "X-GitHub-Api-Version: " + API_VERSION, path]
    if data is not None:
        args += ["--input", "-"]
    body = gh(args, data=data, binary=binary)
    return body if binary else (parse_json(body) if body.strip() else None)


def envelope(result):
    validate_result(result, result["request"])
    if result["source"] != "huggingface-stream" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("Only an Actions HF reference result can be enveloped")
    keys = ("GITHUB_REPOSITORY", "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA",
            "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_EVENT_NAME", "GITHUB_REF")
    values = {k: os.environ[k] for k in keys}
    if values["GITHUB_EVENT_NAME"] != "workflow_dispatch":
        raise ValueError("Reference attestations require workflow_dispatch")
    return {"schema": ENVELOPE, "result": result, "github": values}


def check_run(run, job):
    expected_title = "model-weights-" + job["request"]["request_id"]
    checks = (run["id"] == job["run_id"], run["head_sha"] == job["approved_sha"],
              run["event"] == "workflow_dispatch", run.get("display_title") == expected_title,
              run.get("path") == WORKFLOW, run.get("run_attempt") == 1,
              run["repository"]["full_name"].lower() == job["repository"].lower())
    if not all(checks):
        raise ValueError("Workflow run does not match pinned request/code/repository/attempt")


def dispatch(request, repository, ref, approved_sha):
    validate_request(request)
    if not REPO.fullmatch(repository):
        raise ValueError("Invalid GitHub repository")
    checked_hex(approved_sha, 20)
    if not ref.startswith(("refs/heads/", "refs/tags/")) or len(ref.split("/", 2)[2]) == 0:
        raise ValueError("Use a qualified ref, such as refs/heads/main")
    # An independently pinned commit is required. Never learn the trusted commit
    # from the untrusted node result or from the workflow run being appraised.
    commit = api("repos/%s/commits/%s" % (repository, urllib.parse.quote(ref, safe="")))
    if commit["sha"] != approved_sha:
        raise ValueError("Dispatch ref no longer points to the approved code commit")
    started = int(time.time())
    inputs = {"model_id": request["model_id"], "revision": request["revision"],
              "nonce_client": request["nonce_client"], "request_id": request["request_id"]}
    response = api("repos/%s/actions/workflows/model-reference.yml/dispatches" % repository,
                   method="POST", data={"ref": ref, "inputs": inputs})
    job = {"schema": "confidential-ai/model-reference-job/v1", "request": request,
           "repository": repository, "ref": ref, "approved_sha": approved_sha,
           "dispatched_at": started, "run_id": None}
    if isinstance(response, dict) and type(response.get("workflow_run_id")) is int:
        job["run_id"] = response["workflow_run_id"]
    else:
        # Older API versions return 204. Match the cryptographically random
        # request ID, not "latest run". The caller MUST prevent request ID reuse.
        for _ in range(18):
            listing = api("repos/%s/actions/workflows/model-reference.yml/runs?event=workflow_dispatch&per_page=100" % repository)
            matches = [r for r in listing["workflow_runs"]
                       if r.get("display_title") == "model-weights-" + request["request_id"]]
            if len(matches) > 1:
                raise ValueError("Ambiguous/reused request ID")
            if matches:
                job["run_id"] = matches[0]["id"]
                break
            time.sleep(5)
    if job["run_id"] is None:
        raise RuntimeError("Workflow was dispatched but its run is not yet discoverable; do not blindly redispatch")
    # Fetching immediately may race GitHub indexing; the wait path checks again.
    run = api("repos/%s/actions/runs/%s" % (repository, job["run_id"]))
    check_run(run, job)
    return job


def validate_job(job):
    if not isinstance(job, dict) or set(job) != {
        "schema", "request", "repository", "ref", "approved_sha", "dispatched_at", "run_id"
    } or job["schema"] != "confidential-ai/model-reference-job/v1":
        raise ValueError("Invalid job record")
    validate_request(job["request"])
    if not REPO.fullmatch(job["repository"]):
        raise ValueError("Invalid job repository")
    checked_hex(job["approved_sha"], 20)
    if type(job["run_id"]) is not int or job["run_id"] <= 0:
        raise ValueError("Invalid run ID")
    if type(job["dispatched_at"]) is not int or not job["ref"].startswith(("refs/heads/", "refs/tags/")):
        raise ValueError("Invalid dispatch context")
    return job


def wait_job(job, timeout):
    validate_job(job)
    deadline = time.monotonic() + timeout
    while True:
        run = api("repos/%s/actions/runs/%d" % (job["repository"], job["run_id"]))
        check_run(run, job)
        if run["status"] == "completed":
            if run["conclusion"] != "success":
                raise RuntimeError("Reference workflow did not succeed: " + str(run["conclusion"]))
            return run
        if time.monotonic() >= deadline:
            raise TimeoutError("Reference is still pending; resume with the same job file")
        print("Reference run %d: %s" % (job["run_id"], run["status"]), file=sys.stderr, flush=True)
        time.sleep(min(15, max(0.1, deadline - time.monotonic())))


def unpack_artifact(data, directory):
    if len(data) > MAX_METADATA:
        raise ValueError("Artifact archive exceeds size limit")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if sorted(i.filename for i in entries) != ["bundle.json", "result.json"]:
            raise ValueError("Unexpected archive members")
        if sum(i.file_size for i in entries) > MAX_METADATA:
            raise ValueError("Uncompressed artifact exceeds limit")
        for name in ("result.json", "bundle.json"):
            # No extractall: archive paths cannot escape the destination.
            with (directory / name).open("xb") as f:
                f.write(archive.read(name))


def download_result(job, directory):
    listing = api("repos/%s/actions/runs/%d/artifacts?per_page=100" % (job["repository"], job["run_id"]))
    matches = [a for a in listing["artifacts"]
               if a["name"] == "model-reference-" + job["request"]["request_id"]]
    if len(matches) != 1 or matches[0]["expired"]:
        raise ValueError("Expected one non-expired result artifact")
    artifact = matches[0]
    if artifact["size_in_bytes"] > MAX_METADATA:
        raise ValueError("Result artifact unexpectedly large")
    data = api("repos/%s/actions/artifacts/%d/zip" % (job["repository"], artifact["id"]), binary=True)
    directory.mkdir(parents=True, exist_ok=False)
    unpack_artifact(data, directory)
    return artifact


def check_envelope(document, job):
    if not isinstance(document, dict) or set(document) != {"schema", "result", "github"} or document["schema"] != ENVELOPE:
        raise ValueError("Invalid reference envelope")
    expected = {"GITHUB_REPOSITORY": job["repository"],
                "GITHUB_WORKFLOW_REF": job["repository"] + "/" + WORKFLOW + "@" + job["ref"],
                "GITHUB_WORKFLOW_SHA": job["approved_sha"], "GITHUB_SHA": job["approved_sha"],
                "GITHUB_RUN_ID": str(job["run_id"]), "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": job["ref"]}
    if document["github"] != expected:
        raise ValueError("Signed result has the wrong run/ref/commit context")
    result = validate_result(document["result"], job["request"])
    if result["source"] != "huggingface-stream":
        raise ValueError("Reference did not stream HF weights")
    return result


def verify_downloaded(job, directory, node_result):
    validate_job(job)
    result_path, bundle_path = directory / "result.json", directory / "bundle.json"
    # gh validates signatures, certificate identity, timestamps and artifact
    # subject digest. Do not substitute "the Sigstore URL exists" for this.
    verification = gh(["attestation", "verify", str(result_path), "--hostname", "github.com",
                       "--bundle", str(bundle_path), "--repo", job["repository"],
                       "--signer-workflow", job["repository"] + "/" + WORKFLOW,
                       "--signer-digest", job["approved_sha"], "--source-digest", job["approved_sha"],
                       "--source-ref", job["ref"], "--deny-self-hosted-runners", "--format", "json"])
    checks = parse_json(verification)
    if not isinstance(checks, list) or not checks:
        raise ValueError("No verified artifact attestation")
    write_json(directory / "verified-attestation.json", checks)
    reference = check_envelope(read_json(result_path), job)
    match = compare_results(node_result, reference, job["request"])
    return {"schema": "confidential-ai/reference-comparison/v1", "request": job["request"],
            "reference_attestation_verified": True, "weights_digest_match": match,
            "node_digest": node_result["digest_sha256"], "reference_digest": reference["digest_sha256"],
            "manifest_sha256": reference["manifest_sha256"], "run_id": job["run_id"],
            "run_url": "https://github.com/%s/actions/runs/%d" % (job["repository"], job["run_id"]),
            "approved_workflow_sha": job["approved_sha"],
            "reference_file_sha256": hashlib.sha256(result_path.read_bytes()).hexdigest(),
            "hardware_attestation_verified_by_this_tool": False,
            "locality_or_inference_execution_proven_by_this_tool": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    env = sub.add_parser("envelope")
    env.add_argument("--result", required=True)
    env.add_argument("--output", required=True)
    start = sub.add_parser("dispatch", help="Call only after validating node quote and binding")
    for field in ("request", "repo", "approved-sha", "job"):
        start.add_argument("--" + field, required=True)
    start.add_argument("--ref", default="refs/heads/main")
    finish = sub.add_parser("finish", help="Resume a dispatched job, verify signature, compare results")
    for field in ("job", "node-result", "output-dir"):
        finish.add_argument("--" + field, required=True)
    finish.add_argument("--timeout", type=int, default=7200)
    args = parser.parse_args()
    if args.command == "envelope":
        write_json(args.output, envelope(read_json(args.result)))
    elif args.command == "dispatch":
        if Path(args.job).exists():
            raise ValueError("Job file exists; resume instead of redispatching")
        job = dispatch(read_json(args.request), args.repo, args.ref, args.approved_sha)
        write_json(args.job, job)
        print("https://github.com/%s/actions/runs/%d" % (job["repository"], job["run_id"]))
    else:
        job = validate_job(read_json(args.job))
        node_result = validate_result(read_json(args.node_result), job["request"])
        wait_job(job, args.timeout)
        directory = Path(args.output_dir)
        if directory.exists():
            raise ValueError("Output directory exists; use a new directory for this verification")
        download_result(job, directory)
        comparison = verify_downloaded(job, directory, node_result)
        write_json(directory / "comparison.json", comparison)
        print(json.dumps(comparison))
        if not comparison["weights_digest_match"]:
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
