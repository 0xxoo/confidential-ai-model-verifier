# cc_node / cc_verifier raw-weight Merkle reference

This is a separate, additive protocol. The existing `model-reference.yml` workflow, its result schema, and pinned consumers remain unchanged. New consumers must dispatch `.github/workflows/cc-merkle-reference.yml`; do not compare a legacy serial digest with this Merkle root.

The action independently fetches all `.safetensors` entries at an immutable Hugging Face commit. Each file must have an independent raw SHA256 in HF metadata; unsupported Git-SHA1-only entries are rejected. It streams raw files with four concurrent workers and keeps only the hashes, without storing a 300+ GiB model on the runner or verifier.

- Nonce: exactly 32 decoded bytes; hex is a transport representation.
- Leaf: `SHA256(0x00 || nonce || complete_raw_file_bytes)`; also verify raw SHA256 and byte count against HF metadata.
- Parent: `SHA256(0x01 || left_digest || right_digest)`.
- Order: all safetensors paths in lexicographic ASCII order from independently fetched metadata.
- Tree: split at the largest power of two strictly smaller than the leaf count (RFC9162 shape); do not duplicate an odd leaf. One leaf is its own root; an empty manifest is rejected.
- Manifest: `{model_id, revision, files:[{path,size,sha256}]}` exactly matches the cc-services manifest. Its `manifest_sha256` is SHA256 of the typed CC-E1 encoding, not ordinary JSON serialization.

Result schema: `confidential-ai/cc-merkle-reference/v1`, algorithm `sha256-nonce-file-rfc9162-v1`. The exact result contains nonce, random request ID, full manifest, manifest digest, root, counts and declared timings. The Action signs the exact envelope file using GitHub artifact attestation and publishes that small file and its provenance bundle. No hardware pass or inference grant is issued by this action.

## Verifier obligations

Before accepting `R_expected`, independently pin repository, workflow path, source/workflow commit and allowed branch or tag. Verify the artifact attestation signature and GitHub-hosted runner policy. Compare the attested repository/workflow/run/attempt with the verifier's own registered job, require `workflow_dispatch`, and bind nonce, request ID, model revision, full manifest and manifest digest to the registered challenge. Reject replay, reruns, unapproved code, late results and mismatches. A JSON envelope claiming these values is not enough.

The legacy `github_verifier.py` CLI does **not** consume the new schema. The cc-services verifier includes a separate consumer that pins this workflow, persists dispatch intent and verifies the downloaded artifact before comparison. Live large-model acceptance remains required. Never configure an expected root from an unverified artifact. Running this workflow successfully does not prove that the node used the measured weights for inference or defeats a hostile guest administrator.

Use one of the two service modes: a full new-nonce scan, or fresh environment evidence referencing a still-valid initial model receipt. A cached receipt must keep the original weight verification time; it is not a fresh weight scan.

## Tests

`python3 -m unittest discover -s tests -v` covers raw bytes vs cached digest, nonce changes, stream corruption, three-leaf tree shape, deterministic concurrent order and CC-E1 encoding. Additional interoperability validation compares this module with `cc_common.merkle.scan` in cc-services. Live 306 GiB reference performance has not been measured for this new workflow.
