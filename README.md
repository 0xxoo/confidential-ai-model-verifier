# Confidential AI model weight reference

Compute a fresh challenge digest over **every byte of a pinned Hugging Face model's safetensors files**, then attest the small result using GitHub Actions artifact attestations. A verifier can compare this independently computed reference with a CVM collector's result.

**This is a reference implementation and integration component. It does not obtain or verify TDX quotes, establish collector trust, or prove inference execution.** A matching result alone does not prove files reside in a CVM: a dishonest collector could copy a public reference result. The hardware verifier must independently approve and attest the actual collector and its execution environment.

## What is included

- `model_weights.py`: shared protocol; HF manifest fetch, streaming reference hash, offline local collector, 64-byte REPORTDATA preparation.
- `github_verifier.py`: dispatch a pinned workflow; download its result; verify artifact attestation and approved code identity with `gh`; compare results.
- `.github/workflows/model-reference.yml`: GitHub-hosted Linux job, immutable action pins, small signed output artifact.
- `PROTOCOL.md`: exact byte encoding and integration requirements.

Python 3.11+ on Linux/macOS; Python standard library only. The verifier also needs a recent [GitHub CLI](https://cli.github.com/manual/gh_attestation_verify) supporting the attestation flags used here. The deployed CVM collector needs Linux's no-follow file opening behavior. Windows is unsupported.

## Scope and limits

Version 1 covers **all paths ending in `.safetensors` in the entire HF repository at one exact 40-character commit**. It includes neither tokenizer/configuration files nor inference behavior. If the repository contains multiple alternative models, this scope includes all of them; choose an appropriate repository or define and review a new scope. No file subset, branch name, or moving `main` is accepted as the HF revision.

Only public, ungated HF models are supported. No HF credential is used. HF download data is streamed through memory, so GitHub does not need disk space equal to model size; **GitHub still downloads and reads all bytes for every new challenge**. There is no upstream shortcut for hashing a new nonce followed by all bytes. Limits: 1 TiB, 10,000 files, 20 MiB metadata/result archive, 6-hour workflow. Network failures fail the job; no partial digest is accepted.

## Node integration

1. The verifier stores a fresh client nonce, a unique request ID, approved model ID/revision and policy. Generate nonce with a cryptographically secure random generator (32 bytes); request ID is a fresh 16 bytes. Encode both as lowercase hexadecimal.
2. Prepare a pinned HF manifest during model provisioning. Install the exact same reviewed collector version in the CVM. Model files must be actual regular files, with no symlinks, in a protected read-only snapshot.
3. Hash the local files for each challenge; bind the result to a hardware quote with the same session public key and hardware supplementary evidence.

```bash
python3 model_weights.py manifest --model-id ORG/MODEL --revision HF_COMMIT_SHA --output manifest.json
python3 model_weights.py request --model-id ORG/MODEL --revision HF_COMMIT_SHA \
  --nonce CLIENT_NONCE_HEX --request-id REQUEST_ID_HEX --output request.json
python3 model_weights.py collect --request request.json --manifest manifest.json \
  --model-dir /protected/model --output node-result.json
python3 model_weights.py report-data --request request.json --node-result node-result.json \
  --public-key-der session-public-key.der --policy-sha256 POLICY_DIGEST \
  --supplementary-sha512 HARDWARE_EVIDENCE_DIGEST --output binding.json
```

The hardware integration supplies `bytes.fromhex(binding["report_data_hex"])` to its quote API. `binding.json` itself is **not** a quote. Use a new `model-cvm-v1` evidence protocol; do not silently change an existing hardware-only protocol. See [the exact binding](PROTOCOL.md#hardware-binding).

## Verifier integration

First verify the real hardware quote signature/TCB, approved software measurements, challenge freshness, policy, and the recomputed REPORTDATA. A key-possession check authenticates the node session. Reject unapproved collectors even when their digest matches. Then invoke:

```bash
python3 github_verifier.py dispatch --request request.json \
  --repo 0xxoo/confidential-ai-model-verifier --ref refs/heads/main \
  --approved-sha REVIEWED_GITHUB_COMMIT_SHA --job job.json
python3 github_verifier.py finish --job job.json --node-result node-result.json \
  --output-dir verified-reference --timeout 7200
```

Pin `REVIEWED_GITHUB_COMMIT_SHA` in verifier policy after code review, independently of the node and workflow response. Do not automatically trust whatever `main` currently contains. Dispatch fails if the ref has moved from the approved SHA. After an approved update, update the policy explicitly.

`dispatch` is asynchronous. Store `job.json` in protected verifier state keyed by request ID; resume the same job after a timeout. Never use "latest successful run". If dispatch returns ambiguously, reconcile using the unique request ID; do not automatically create another run. Reruns are rejected; begin a new challenge instead. A server wrapper must add authenticated callers, per-user limits, an approved model allowlist, size/time budgets, unique nonce/request storage, and persistent task status. **These scripts are not a public unauthenticated HTTP service.**

`finish` downloads only `result.json` and `bundle.json`, verifies signature, artifact subject digest, repository, workflow, approved source/signer commits and source ref, rejects self-hosted runners, and checks the signed request/run context. It writes `comparison.json`. Exit 0 means reference comparison matched, 2 means mismatch; errors raise and exit nonzero. The output explicitly says hardware and locality were not verified by this tool. The host verifier makes the full decision.

Use a GitHub App installation token restricted to this repository: Actions read/write for dispatch and retrieval, Contents read. For the documented local smoke test, an already authenticated `gh` account works. Keep dispatch credentials on the verifier, never on clients or nodes. Never put tokens in command arguments, result files or logs.

## Artifact attestation and cost

The workflow uses `actions/attest` to attest **the exact bytes of `out/result.json`** and uploads that file with the generated Sigstore bundle. It does not attest the model as a stored GitHub artifact. Verification checks cryptographic evidence, not just the existence of an Actions page.

GitHub currently makes artifact attestations available in public repositories on its ordinary plans; private/internal repositories require GitHub Enterprise Cloud. Standard GitHub-hosted runners for public repositories are free under GitHub's documented terms. Artifact storage, larger runners and private-repository usage have separate rules. Each challenge still consumes download bandwidth and runner time. Check [attestation availability](https://docs.github.com/en/actions/concepts/security/artifact-attestations) and [Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions). This workflow retains only small result artifacts for seven days. Archive verified results and bundles on the verifier if longer retention is needed.

All workflow inputs/results are public. Nonces are public random challenges; do not put secrets or sensitive identifiers in them.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Tests cover the byte transcript, changed nonce, altered/truncated/extra files, symlinks, path traversal, duplicate JSON keys, quote binding, run identity, signature failure and digest mismatch. They use synthetic weight bytes; the protocol hashes bytes and does not parse or execute model files.

No model code, pickle, `trust_remote_code`, or inference engine is executed by this workflow. A real small-model Actions smoke test is additionally needed when deploying to a new repository.
