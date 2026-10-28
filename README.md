# Pinned OpenClaw Windows builder

Dedicated public-source-only GitHub Actions builder. **Each execution requires explicit owner approval.**
This is a preparation bundle, not an OpenClaw runtime distribution.

Inputs: OpenClaw commit `aedd9f3f56585d92ed14947df8c84ef6354f64cc`,
Node24.22.1 Windows x64, native pnpm12.15.0. No upstream source is vendored.
No model/provider login, personal configuration, private checkout or secrets
are needed. Proposed repository: `tranquocvy/openclaw-windows-builder`;
availability and creation are not asserted.

Files intended for this repository are listed in [PUBLIC_MANIFEST.sha256](PUBLIC_MANIFEST.sha256).
It excludes itself to avoid a circular hash. Copy only listed files plus that
manifest into a new checkout; never publish a parent directory or its history.

The [workflow](.github/workflows/build-windows.yml) permits only manual dispatch,
has an event/main/first-attempt admission gate, exact action SHAs, read-only contents permission,
one standard windows-2025 job, maximum60min, no cache/auto-retry, artifact≤250MiB
and retention1day. Attempt1 guard/concurrency do not cap all fresh dispatches.
Do not enable or dispatch until the owner approves the exact revision,
repository/settings, one-run allowance, security residuals and cost posture.

[Build.ps1](scripts/Build.ps1) inherits pinned public Git acquisition and verified
portable Node/pnpm, frozen offline installation without lifecycle/pnpmfile or
automatic runtime/manager switching, then the source-supported cliStartup profile.
Explicit build imports still execute dependencies. No installer/repair/full-build
fallback is authorized. Do not execute this script on a personal workstation.

[Candidate gate](scripts/test_candidate.py) uses Python standard library only,
does not extract or execute candidate code, and checks ZIP paths/types/collisions,
expanded size, file hashes/inventory, source/run receipts, Node identity,
native package-owner inventory, scripts, link topology and selected secret patterns.
It runs before upload. Policy is in [artifact-policy.json](policy/artifact-policy.json).
Unknown native owners, missing assets, layout issues or cap violations stop upload;
no silent policy relaxation. Dependencies are not made trustworthy by a hash or
by being listed as an expected owner. Only package-byte comparison against pinned
registry integrity plus separate review can qualify the payload.

Candidate output: one ZIP, checksum and consistency report. Status remains
`QUARANTINED_CANDIDATE`, `hostExecution=false`. It contains regular files and a
link manifest as data, no active upstream root wrapper or host launch/repair helper.
The conservative workspace dependency closure may exceed limits; failure is a
valid outcome. It is not a directly runnable/minimal release. Public artifacts
and Actions logs may be visible to other people; deletion/expiry does not revoke
copies. No release/package/container/external publication is performed.

The gate is **not an independent security boundary**: dependency code on an
administrator-capable hosted runner can modify checks/output and reach ephemeral
runner/artifact authority despite environment filtering. This workflow does not
enforce registry-only acquisition or zero-egress build. Public internet acquisition
and Actions artifact traffic need explicit acceptance or a separately proven policy.
No long-lived repository/model secrets or private data belong on this runner.

Before execution, verify public visibility, standard runner eligibility/rates,
Actions/storage settings and applicable spending stops in the actual account.
Public standard-runner compute is documented as free; that does not establish
every account/SKU/storage configuration is cost-free. Other subscriptions do not
supply GitHub Actions credit. No larger runner or paid fallback is selected.

After an approved single dispatch, record its run ID and immediately disable the
workflow (disabling does not cancel an existing run). Reconcile that exact run,
artifact ID/digest, cleanup state and usage before any new authorization. No
automatic download or host startup. On a separate trusted host, use a reviewed
copy of the checker and policy (not tools from the candidate), inspect the archive
without execution, independently compare package/source identities and native
files, then obtain explicit artifact-bound runtime approval. Normal loopback-only
Gateway smoke requires its own synthetic profile, no-repair entry qualification,
process-tree egress boundary, deadlines and shutdown reconciliation. No worker/model
activation follows from a successful build or consistency check.
