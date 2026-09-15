# Model challenge protocol v1

## Claim

Under the verifier's approved collector and protected CVM environment, a successful collection records that the named local weight files were read for this challenge and matched an independent HF reference. It does not prove which weights were loaded into a GPU, which model executed a request, persistence after scanning, or the absence of additional models elsewhere.

A hardware quote authenticates its user-data field; hardware does not interpret model names, paths or hashes. A malicious but otherwise valid guest can request a quote for arbitrary data. Approved measured boot plus runtime protection of the collector, configuration, kernel, filesystem and quote/session-key access are prerequisites. Merely publishing this source or hashing its executable is insufficient.

## Request and manifest

`request` has exactly these fields:

```json
{"schema":"confidential-ai/model-challenge/v1","request_id":"32 lowercase hex characters","nonce_client":"64 lowercase hex characters","model_id":"ORG/REPO","revision":"40 lowercase hex characters","scope":"all-safetensors-v1","model_verification_required":true}
```

The nonce represents 32 **decoded bytes**, not 64 UTF-8 hex characters. Request IDs represent 16 random bytes. The verifier registers the request before sending it to the node, with its own creation time and deadlines; it rejects reuse. The caller selects an approved exact HF commit. The HF metadata response must report that exact commit.

Manifest fields are `schema=confidential-ai/hf-weight-manifest/v1`, `scope`, `model_id`, `revision`, and `files`. Each file entry contains `path`, integer `size`, `hf_digest_algorithm`, and `hf_digest`. Entries cover every `.safetensors` path returned for the pinned repository, sorted lexicographically by ASCII path. Paths must be relative ASCII paths without empty, dot, parent, backslash or control-character components. No duplicates. HF LFS metadata supplies raw `sha256`; small non-LFS Git files use `git-sha1`, defined as SHA1(`ASCII("blob " + decimal_size) || 0x00 || file_bytes`). All bytes additionally enter the SHA256 challenge digest.

## Exact digest

Define `C(x)` as Python `json.dumps(x, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')`. Identities contain no floating-point values. Reject duplicate JSON keys and unsupported/extra schema fields. Sizes/times are integers, not booleans.

```text
I = C({"request": request, "manifest": manifest})
D = SHA256(
    ASCII("confidential-ai/model-weight-challenge/v1") || 0x00
    || hex_decode(request.nonce_client)
    || uint64_big_endian(byte_length(I)) || I
    || file_1_bytes || file_2_bytes || ... || file_N_bytes
)
```

The manifest fixes file names, ordering and byte boundaries. Including the request additionally binds the model, exact revision, scope and verification requirement. This is intentionally a domain-separated, fully specified form of `hash(nonce + weights)`; it is not a hash of precomputed weight hashes. Files need not be modified to insert the nonce. Each file's actual length and independent HF checksum must also match. There is one reading pass and two hash states (challenge hash plus raw file hash).

Node collection has no network reads. It checks the exact local safetensors path set, rejects symlinks/nonregular files, and checks metadata before/after reading and before finishing. These checks catch ordinary changes; they do **not** defeat a malicious guest root, mutable remote mounts, or a compromised kernel. Provision a protected read-only local snapshot and prevent mounts/files changing through collection and quote generation. A read-only bind mount alone is insufficient if another writable mount can change the same backing files.

## Result

The result schema is `confidential-ai/model-weight-result/v1`. It contains `request`, `manifest`, `manifest_sha256=hex(SHA256(C(manifest)))`, `digest_sha256=hex(D)`, `total_bytes`, `file_count`, `source`, `started_at`, `finished_at`, `elapsed_milliseconds`. Source is `local-filesystem` on the node and `huggingface-stream` in Actions. Times are node/runner assertions, not trusted hardware timestamps.

Compare full request and manifest and challenge digest; do not compare complete result JSON because source/times differ.

## Hardware binding

For a new evidence protocol `model-cvm-v1`, compute:

```text
record = {
  "protocol_version": "model-cvm-v1",
  "request": request,
  "node_result_sha256": hex(SHA256(C(node_result))),
  "node_public_key_sha256": hex(SHA256(public_key_SPKI_DER)),
  "policy_digest": hex(SHA256(C(verifier_policy))),
  "supplementary_evidence_sha512": hex(SHA512(C(hardware_supplement)))
}
REPORTDATA = SHA512(ASCII("confidential-ai/model-cvm-report/v1") || 0x00 || C(record))
```

Exactly 64 bytes go into the TDX quote API. The integration must define and validate `hardware_supplement` consistently on both ends, covering its original CCEL/device/GPU evidence and required topology bindings, excluding the quote itself to avoid a circular hash. Preserve the original hardware schema as a nested object if needed. Do not include a self-asserted `model_weights_verified=true`: that is the verifier's decision.

The verifier reconstructs this from the actual received request, result, DER key, policy and supplemental evidence and compares the 64 bytes with the **cryptographically verified quote body's** REPORTDATA. It separately verifies CCEL replay/RTMRs, accepted measurements, TCB/debug policy, GPU evidence if required, and key possession. This code supplies the binding calculation only; it does not perform those hardware checks.

Use REPORTDATA for per-request data. Do not modify RTMR[3] as part of this implementation: extending a register changes cumulative measurement state and requires event-log replay and concurrency design. Existing boot/runtime measurements remain checked by the hardware verifier.

## GitHub provenance

The workflow outputs an envelope with schema `confidential-ai/github-model-reference/v1`, `result`, and `github`. The latter records `GITHUB_REPOSITORY`, `GITHUB_WORKFLOW_REF`, `GITHUB_WORKFLOW_SHA`, `GITHUB_SHA`, `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_EVENT_NAME`, and `GITHUB_REF` from the workflow environment. Attestation's subject is the exact envelope file bytes, including its trailing newline.

Require a successful `workflow_dispatch` from an independently approved repository/workflow/source SHA on a GitHub-hosted runner. Verify the artifact attestation with the CLI's repository, signer-workflow, signer-digest, source-digest, source-ref and deny-self-hosted-runners policies. Then validate the signed request and run context against protected verifier job state. The envelope's identity assertions alone are not a substitute for certificate verification. The approved code is what gives meaning to the signed computation output.

The reference code downloads the pinned HF manifest independently; it never accepts a node-supplied manifest or digest as its expected result. Inputs never select shell code, download hosts, local paths, or a model code loader.

## Freshness and final decision

Issue the challenge before collection. Receive and validate node evidence within a configured **collection deadline**, record its receipt, then schedule the reference job. Permit a separate longer reference deadline while retaining the original challenge/quote relationship. Late reference completion does not refresh the original evidence or establish the node's state at completion time. Any inference-session token needs the system's own short-lived authorization policy; this audit does not extend it.

Final `model_weights_verified=true` requires all of: fresh registered challenge; valid hardware evidence; independently approved collector/runtime protections; correct REPORTDATA/session binding; verified GitHub provenance for approved code; identical request, manifest and challenge digest. Otherwise return pending, mismatch, error, or unsupported collector as appropriate. An explicitly requested model check must never become a hardware-only success.

The nonce prevents reusing a previously calculated challenge digest for a new challenge under standard hash assumptions. It does not prove an exact calculation time or physical location. Public reference output can be copied by untrusted software; software attestation and environment protection remain essential.
