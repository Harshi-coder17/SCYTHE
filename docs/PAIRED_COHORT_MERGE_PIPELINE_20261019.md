# Reviewed cohort merge pipeline

`lightgbm_dataset/build_reviewed_retry_cohort.py` now accepts several immutable
`--quality` directories and collection `--runs`. The latest provisional plan is
`lightgbm_dataset/prospective_collection_v1/merge_plan_reviewed_v5_preflight_pending_20261019_v2/`.
It has four checksummed payloads plus the checksum manifest: input bindings and
selection preview, every quality judgment, every attempt's selection reason,
and exact builder source.
No embeddings or candidate were trained for this plan. Frozen v4 remains intact.

## Selection rules

- Verify all collection/review manifests and referenced image/scan bytes first.
- Preserve each source review and its authority; machine decisions cannot
  replace human or unclassified protected reviewer decisions. Conflicting
  authoritative decisions or image identities quarantine that capture.
- Quarantine label/domain conflicts and human-confirmed disputed-label domains.
  Quality acceptance never independently establishes the phishing/benign label.
- Select the newest quality-accepted valid capture for each canonical URL using
  its actual capture/decision timestamps, irrespective of later failed or
  quality-pending attempts. Retain older captures and acquisition/review reasons.
  Selection never consults model probabilities.
- Apply protected requested/redirect-domain exclusions and connected grouping
  across domain, known campaign, and exact/near-duplicate images before an
  approximately 80/20 grouped split. Unknown campaigns remain unknown.
- Optionally derive corrected sandbox evidence only from verified saved,
  request-bound, completed contemporaneous metadata. Original scan evidence is
  retained; incomplete/false/malformed evidence remains unavailable.

## Current provisional inventory

Seven completed runs and five review directories cover 367 retained attempts
and 158 distinct canonical targets. Sixty quality-accepted URL captures reduce
to 58 after two protected requested/redirect-domain exclusions: 23 feed-supported
phishing and 35 proxy benign. They form 51 connected visual/domain groups,
including the five identical imToken captures in a single group. The preview
contains 46 training and 12 validation records. This is development supervision
only; independent release labels remain zero.

The older preflight and its failed attempts are not counted as new coverage
when they repeat a newer URL. Salvaged earlier captures retain their historical
timestamps. The first provisional plan is retained separately; this second plan
adds the subsequently reviewed nine-record checkpoint.

## Build after the 200-attempt preflight is finalized and reviewed

First load the concrete existing source paths from the verified provisional
plan. Append the **actual** newly finalized run and review paths, then build a
new immutable dataset/candidate version using the research runtime. Replace the
two placeholder paths below with those real completed artifacts; do not use a
running or unchecked run. The placeholders intentionally are not runnable data.

```powershell
$plan = Get-Content -Raw lightgbm_dataset/prospective_collection_v1/merge_plan_reviewed_v5_preflight_pending_20261019_v2/merge_plan.json | ConvertFrom-Json
$runRoots = @($plan.input_binding.runs.PSObject.Properties.Name)
$reviewRoots = @($plan.input_binding.quality.PSObject.Properties.Name)
$runRoots += (Resolve-Path 'lightgbm_dataset/prospective_collection_v1/runs/<completed-200-run-id>').Path
$reviewRoots += (Resolve-Path 'lightgbm_dataset/prospective_collection_v1/<completed-200-quality-review>').Path
$env:PYTHONPATH = (Resolve-Path lightgbm_dataset/_deps).Path
& mobileclip-dataset/.venv/Scripts/python.exe lightgbm_dataset/build_reviewed_retry_cohort.py --runs @runRoots --quality @reviewRoots --output lightgbm_dataset/prospective_reviewed_dev_v5 --train-output lightgbm_dataset/prospective_reviewed_dev_v5_fusion_v2 --repair-sandbox-export
```

Use an unused version if v5 already exists. Add `--plan-only` and omit
`--train-output` to create another selection preview instead. Human judgments,
original artifacts, and failed attempts must remain preserved; no failed
quality gate, proxy label, or synthetic observation becomes release evidence.

## Verification

All 82 dataset tests passed after the multi-source implementation. The focused
suite covers later-unavailable/older-usable salvage, distinct captures for one
URL, deterministic timestamp selection independent of model scores, conflicting
reviews, reviewer preservation, tampered manifests/images, label conflicts,
connected grouping, cache integrity, and training/runtime evidence parity.
Ruff passes for the changed builder and tests.
