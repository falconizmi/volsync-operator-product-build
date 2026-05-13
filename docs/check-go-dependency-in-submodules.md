# Checking Go Dependencies Across Submodules (CVE Triage)

When a CVE is reported against a Go package, we need to determine which submodules in `volsync-operator-product-build` depend on it, at what version, across each active release branch, and whether CVE-patches already address it.

The script `hack/check-go-dep.sh` automates this.

## Quick Reference

```bash
# By package name
./hack/check-go-dep.sh golang.org/x/image

# By CVE ID
./hack/check-go-dep.sh CVE-2026-33813

# By CVE URL
./hack/check-go-dep.sh "https://www.cve.org/CVERecord?id=CVE-2026-33813"

# Specific branches
./hack/check-go-dep.sh --branches release-0.14,release-0.15 golang.org/x/net

# ACM version → release branch (ACM X.Y.Z → release-(X-2).(Y-1))
./hack/check-go-dep.sh --acm 2.16.0 golang.org/x/image

# All upstream release branches
./hack/check-go-dep.sh --all golang.org/x/net

# Skip fetch (faster, uses cached state)
./hack/check-go-dep.sh --no-fetch golang.org/x/image
```

## What It Checks

### go.mod Locations Per Branch

The script reads go.mod files **without checking out** the branch — it uses `git ls-tree` + `git -C <submodule> show <commit>:go.mod` for submodules and `git show <branch>:<path>` for in-tree files.

**Submodule go.mods** (the actual dependency declarations):

| Label | Source |
|-------|--------|
| `volsync` | `volsync/go.mod` — main volsync operator |
| `volsync/restic` | `volsync/mover-restic/restic/go.mod` — restic mover |
| `volsync/minio-go` | `volsync/mover-restic/minio-go/go.mod` — minio-go (used by restic) |
| `rclone` | `rclone/go.mod` |
| `syncthing` | `syncthing/go.mod` |
| `diskrsync` | `diskrsync/go.mod` |

**CVE-patches go.mods** (override submodule deps via `replace` directives):

| Label | Source |
|-------|--------|
| `CVE-patch/rclone` | `CVE-patches/rclone_patch_deps/go.mod` |
| `CVE-patch/restic` | `CVE-patches/restic_patch_deps/restic/go.mod` |
| `CVE-patch/minio-go` | `CVE-patches/restic_patch_deps/minio-go/go.mod` |

CVE-patches don't exist on all branches (e.g., not on release-0.12/0.13 or main). The script shows `n/a` when a go.mod doesn't exist on a branch.

### Sub-Package to Module Matching

CVE records sometimes reference sub-packages (e.g., `golang.org/x/net/html`) while go.mod lists the module root (`golang.org/x/net`). The script handles this by trying the full path first, then progressively stripping the last segment until a match is found.

## CVE Mode

When given a CVE ID or URL, the script:

1. Fetches CVE data from `https://cveawg.mitre.org/api/cve/{CVE_ID}`
2. Extracts affected package names and version ranges
3. For each found dependency, compares the version against the affected range
4. Outputs one of:
   - `VULNERABLE` — version is in the affected range
   - `FIXED` — version is outside the affected range (upstream updated)
   - `PATCHED` — a CVE-patch `replace` directive overrides to a fixed version

### CVE API Caveats

The CVE API data quality varies. Some entries have:
- `packageName: null` — the script falls back to the `product` field
- Non-Go module paths (e.g., `grpc-go` instead of `google.golang.org/grpc`) — the script warns and suggests running again with the actual module path
- Non-standard version formats (e.g., `"< 1.79.3"` instead of `{version:"0", lessThan:"1.79.3"}`) — the script normalizes these

When the CVE metadata doesn't include a valid Go module path, run the script again with the package name directly:
```bash
./hack/check-go-dep.sh google.golang.org/grpc
```

## ACM Version Mapping

ACM version X.Y.Z maps to VolSync release-(X-2).(Y-1):

| ACM Version | VolSync Release |
|-------------|-----------------|
| 2.14.x | release-0.13 |
| 2.15.x | release-0.14 |
| 2.16.x | release-0.15 |
| 2.17.x | release-0.16 |

## How CVE-Patches Work

The `CVE-patches/` directory contains patched `go.mod`/`go.sum` files organized by tool:

```
CVE-patches/
├── patch_rclone.sh              # copies patched go.mod into rclone during build
├── patch_restic.sh              # copies patched go.mod into restic during build
├── rclone_patch_deps/
│   ├── go.mod                   # rclone's go.mod with replace directives
│   └── go.sum
└── restic_patch_deps/
    ├── minio-go/
    │   ├── go.mod
    │   └── go.sum
    └── restic/
        ├── go.mod               # restic's go.mod with replace directives
        └── go.sum
```

The patched go.mod files use Go `replace` directives to pin vulnerable dependencies to fixed versions. For example:
```
replace google.golang.org/grpc => google.golang.org/grpc v1.79.3
```

These are applied during the container build (`Dockerfile.rhtap`) before `go mod download`.

CVE-patches vary per release branch — some branches may not need patches if the submodule version is already updated. On release-0.16, rclone patches were removed (NOOP) because rclone v1.74.0 no longer needed them.

## How Cross-Branch Reading Works

The script reads go.mod files from any branch without checking it out:

```bash
# For submodules: get the pinned commit, then read from the submodule's git history
submod_commit=$(git ls-tree upstream/release-0.15 volsync | awk '{print $3}')
git -C volsync show ${submod_commit}:go.mod

# For CVE-patches (regular files in the tree):
git show upstream/release-0.15:CVE-patches/rclone_patch_deps/go.mod
```

This requires that submodule commits are fetched locally. The script runs `git fetch` for upstream and all submodules at startup (skippable with `--no-fetch`).

## Manual Fallback

If the script isn't available, the same check can be done manually:

```bash
# 1. Fetch
git fetch upstream
git -C volsync fetch

# 2. Get submodule commit pinned on a branch
git ls-tree upstream/release-0.15 volsync | awk '{print $3}'

# 3. Read go.mod from that commit
git -C volsync show <commit>:go.mod | grep 'golang.org/x/image'

# 4. Check CVE-patches
git show upstream/release-0.15:CVE-patches/rclone_patch_deps/go.mod | grep 'golang.org/x/image'
```

## Dependencies

The script requires: `jq`, `curl`, `git`. All are standard on Fedora/RHEL dev environments.

## Output Example

```
$ ./hack/check-go-dep.sh --no-fetch golang.org/x/image

--- release-0.14 ---
  volsync                  not found
  volsync/restic           not found
  rclone                   not found
  syncthing                not found
  diskrsync                not found
  CVE-patch/rclone         not found
  CVE-patch/restic         not found

--- release-0.15 ---
  volsync                  not found
  rclone                   v0.32.0 (indirect)
  syncthing                not found
  diskrsync                not found
  CVE-patch/rclone         v0.32.0 (indirect)

--- release-0.16 ---
  volsync                  not found
  rclone                   v0.39.0 (indirect)
  syncthing                not found
  diskrsync                not found
  CVE-patch/rclone         n/a
```
