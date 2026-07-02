# CVE Triage Workflow

When given a CVE ID and one or more ACM Jira ticket links, follow this workflow.

IMPORTANT: Before starting, create tasks (TaskCreate) for every step of this workflow.
One of those tasks MUST be "Add regression test to test-cve-triage.sh" (Step 5).
Do not mark the triage as complete until the test task is done.

## Step 1 — Run the triage script

Run `hack/cve-triage.sh <CVE-ID>` (without `--no-fetch` to ensure branches are up to date). Use `-v` for verbose output when deeper investigation is needed. Verify every detail of the output: which branches are active, which submodules import the vulnerable package, what versions they have, and whether they fall within the CVE bounds.

## Step 2 — Investigate reachability

If a submodule imports the vulnerable package at a version within CVE bounds, determine whether the vulnerable code is actually reachable from VolSync's execution paths:

- Which files in the submodule import the package? What feature area do they belong to?
- How does VolSync invoke the submodule? (Check the mover scripts, e.g. mover-rclone/)
- Does VolSync reference the feature keyword (e.g. "sftp") anywhere in its own source?
- Is the CVE server-side only, client-side only, or both? Scope the analysis accordingly.

Verify by reading actual code and scripts — do not assume.

## Step 3 — Check the Jira tickets

Read each ticket. The title indicates which ACM version it targets (e.g. rhacm-2.15 = ACM 2.15 = VolSync release-0.14). See the Version mapping section in the root CLAUDE.md for the formula.

Check existing comments on the tickets for context or related CVEs.

## Step 4 — Write Jira comments

Present the analysis for review before writing comments. Write one comment per ticket. Adapt the technical details to the specific CVE but keep the structure and tone consistent.

### Comment templates

**Vulnerable version present but code is unreachable:**

    VolSync is not affected on release-X.YY (aligns with ACM Z.ZZ).

    <One sentence: what CVE affects, what package, fix version>. On VolSync
    release-X.YY, only the <submodule> submodule imports this package (at
    vA.B.C, below the fix version).

    <Where the vulnerable code paths are, why VolSync does not reach them,
    what VolSync actually uses instead, evidence that the feature is not
    referenced in VolSync source.>

    All other VolSync submodules (<full list>) do not import <package>.

    The vulnerable code is present in the binary but is unreachable from
    VolSync's execution paths.

  Example (CVE-2026-46595, source-address validation bypass):

    VolSync is not affected on release-0.15 (aligns with ACM 2.16).

    Only the rclone submodule imports golang.org/x/crypto/ssh (at
    v0.45.0, below the fix version). The vulnerable code path is in
    ssh.NewServerConn, which rclone uses in cmd/serve/sftp/server.go.
    VolSync never invokes "rclone serve sftp" — it only uses rclone
    sync/copy as a client.

**Package already at or above the fix version:**

    VolSync is not affected on release-X.YY (aligns with ACM Z.ZZ).

    <One sentence: what CVE affects, what package, fix version>. On VolSync
    release-X.YY, <submodule> ships with <package> vA.B.C, which already
    includes the fix. All other VolSync submodules do not import the
    affected package.

  Example (CVE-2026-39829, oversized RSA/DSA key DoS):

    VolSync is not affected on release-0.16 (aligns with ACM 2.17).

    Only the rclone submodule imports golang.org/x/crypto/ssh. On
    release-0.16, rclone ships with golang.org/x/crypto v0.52.0,
    which already includes the fix.

**Not affected — affected package not imported by any submodule:**

    VolSync is not affected on release-X.YY (aligns with ACM Z.ZZ).

    No VolSync submodule imports <package>.

  Example (CVE-2026-39832, ssh/agent key restriction bypass):

    VolSync is not affected on release-0.15 (aligns with ACM 2.16).

    No VolSync submodule imports golang.org/x/crypto/ssh/agent.

**Not affected — affected symbol not used by the submodule:**

    VolSync is not affected on release-X.YY (aligns with ACM Z.ZZ).

    Only the <submodule> submodule imports <package>, and <submodule>
    does not use <affected symbol> anywhere in its codebase.

  Example (CVE-2026-39835, CertChecker panic):

    VolSync is not affected on release-0.16 (aligns with ACM 2.17).

    Only the rclone submodule imports golang.org/x/crypto/ssh, and
    rclone does not use CertChecker anywhere in its codebase. VolSync
    only uses rclone as a client, never as an SSH server.

**Affected — vulnerable code is reachable:**

    VolSync is affected on release-X.YY (aligns with ACM Z.ZZ).

    Only the <submodule> submodule imports <package>.
    <One sentence: why the vulnerable code path is reachable.>

    Fix pushed on release-X.YY, will ship with ACM Z.ZZ.z.

  Example (CVE-2026-39829, oversized RSA/DSA key DoS):

    VolSync is affected on release-0.15 (aligns with ACM 2.16).

    Only the rclone submodule imports golang.org/x/crypto/ssh. Users
    can configure SFTP backends via RcloneConfig, making rclone act
    as an SSH client, which reaches the vulnerable code path.

    Fix pushed on release-0.15, will ship with ACM 2.16.3.

**Branch out of support:**

    VolSync vX.YY.z (aligns with ACM Z.ZZ) has gone out of support.

  For operator-bundle tickets, add the bundle clarification even on out-of-support branches:

    VolSync vX.YY.z (aligns with ACM Z.ZZ) has gone out of support.

    The operator-bundle image contains only YAML manifests, no Go code.
    <package> is not present in the bundle image.

  Example (CVE-2026-39835, CertChecker panic):

    VolSync 0.13.z (aligns with ACM 2.14) has gone out of support.

## Step 5 — Add a regression test

After triaging a CVE, ALWAYS add it as a new test case in `hack/test-cve-triage.sh`, even if a similar CVE is already tested. Every distinct CVE ID gets its own test — more coverage is always better for catching regressions. Skip only if the exact same CVE ID is already in the test file.

1. Add a `run_test` call with the CVE ID, expected exit code, required patterns, and forbidden patterns.
2. Cache the CVE and OSV API responses as fixtures in `hack/test-fixtures/`:
   - `curl -sf "https://cveawg.mitre.org/api/cve/<CVE-ID>" > hack/test-fixtures/<CVE-ID>.json`
   - Look up the GO-* ID from the CVE references, then: `curl -sf "https://api.osv.dev/v1/vulns/<GO-ID>" > hack/test-fixtures/<GO-ID>.json`
3. Run `bash hack/test-cve-triage.sh` to verify the new test passes in offline mode.

Exit code conventions:
- 0 = NOT_AFFECTED (server-only, symbol not used, package not imported, above fix version)
- 2 = NEEDS_HUMAN_REVIEW (client-side reachable, needs further investigation)

### Comment formatting rules

- Do not use backtick characters in comments — they are hard to copy into Jira
- Always mention VolSync explicitly — tickets are filed under ACM
- Use "(aligns with ACM Z.ZZ)" to clarify the version relationship
- List all submodules consistently (e.g. volsync, restic, minio-go, syncthing, diskrsync)
- Each comment must be self-contained — do not reference other comments or tickets
