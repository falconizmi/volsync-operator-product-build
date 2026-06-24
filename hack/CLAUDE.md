# CVE Triage Workflow

When given a CVE ID and one or more ACM Jira ticket links, follow this workflow.

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

**Package already at or above the fix version:**

    VolSync is not affected on release-X.YY (aligns with ACM Z.ZZ).

    <One sentence: what CVE affects, what package, fix version>. On VolSync
    release-X.YY, <submodule> ships with <package> vA.B.C, which already
    includes the fix. All other VolSync submodules do not import the
    affected package.

**Branch out of support:**

    VolSync vX.YY.z (aligns with ACM Z.ZZ) has gone out of support.

### Comment formatting rules

- Do not use backtick characters in comments — they are hard to copy into Jira
- Always mention VolSync explicitly — tickets are filed under ACM
- Use "(aligns with ACM Z.ZZ)" to clarify the version relationship
- List all submodules consistently (e.g. volsync, restic, minio-go, syncthing, diskrsync)
- Each comment must be self-contained — do not reference other comments or tickets
