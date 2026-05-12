# Checking RPM Lockfile Freshness Across Branches

When Konflux/Mintmaker updates base image digests (e.g., `registry.redhat.io/ubi9/ubi-minimal`), the `rpms.lock.yaml` may become stale because available RPM versions change with new base images. The script `hack/check-rpm-lockfile.sh` automates checking whether lockfiles need regeneration.

**Note:** This script lives on the `main` branch only. Run it from a `main` checkout — it checks release and PR branches remotely via git worktrees.

## Quick Reference

```bash
# Switch to main first
git checkout main

# Check all active release branches + open PRs
./hack/check-rpm-lockfile.sh

# Only active release branches (those with .tekton/ pipelines)
./hack/check-rpm-lockfile.sh --releases-only

# Only open PR branches
./hack/check-rpm-lockfile.sh --prs-only

# Specific branches
./hack/check-rpm-lockfile.sh --branches release-0.15,release-0.16

# Fetch upstream first (default: uses cached state)
./hack/check-rpm-lockfile.sh --fetch
```

## Prerequisites

1. **podman** — for running the rpm-lockfile-prototype container
2. **registry.redhat.io access** — `$HOME/.docker/config.json` must have credentials
3. **gh CLI** — for discovering open PRs (not needed with `--releases-only` or `--branches`)
5. **git fetch upstream** — run before the script if you want fresh data, or use `--fetch` flag
4. **rpm-lockfile-prototype image** — the script auto-builds from `Containerfile` if missing

### Initial Setup

The `Containerfile` in the repo root builds the rpm-lockfile-prototype tool image. If the image doesn't exist, the script builds it automatically. To build manually:

```bash
podman build -t localhost/rpm-lockfile-prototype:latest -f Containerfile .
```

For registry.redhat.io access, ensure your `$HOME/.docker/config.json` has valid credentials. You can log in with:

```bash
podman login registry.redhat.io
```

## What It Checks

### Branch Discovery

The script finds branches to check from two sources:

1. **Active release branches** (`upstream/release-*`): Branches that have both a `.tekton/` directory (meaning they're actively built via Konflux) and an `rpms.lock.yaml` file.

2. **Open PR branches**: Branches from open PRs in the upstream repo that contain `rpms.lock.yaml`.

### Per-Branch Check

For each branch, the script:

1. Creates an isolated git worktree (doesn't disturb your current checkout)
2. Initializes submodules
3. Runs the rpm-lockfile-prototype tool to regenerate `rpms.lock.yaml`
4. Compares the regenerated file against the current one
5. Reports whether the lockfile is up-to-date or needs changes
6. Cleans up the worktree

Each branch uses its own `rpms.in.yaml` — these can differ between releases (e.g., release-0.15 uses `perl` while release-0.16 uses `python3`).

## Output

```
RPM Lockfile Check

Fetching upstream...

Checking 3 branch(es):

release-0.14
  UP-TO-DATE

release-0.15
  NEEDS UPDATE

  rpms.lock.yaml | 42 +++++++++++++++++++-----------
  1 file changed, 26 insertions(+), 16 deletions(-)

release-0.16
  UP-TO-DATE

=== Summary ===

  ✓ release-0.14
  ✗ release-0.15
  ✓ release-0.16

1 branch(es) need RPM lockfile updates.
```

The script exits with code 1 if any branch needs updates, 0 if all are up-to-date.

## Manually Updating a Stale Lockfile

When the script reports a branch needs an update, follow the standard workflow:

```bash
# Checkout the branch
git checkout -b <branch-name> upstream/<branch>
git submodule update --init

# Regenerate the lockfile
container_dir=/work
podman run --rm \
  -v "${PWD}:${container_dir}:z" \
  -v "$HOME/.docker/config.json:/root/.docker/config.json:ro,z" \
  localhost/rpm-lockfile-prototype:latest \
  --outfile="${container_dir}/rpms.lock.yaml" \
  "${container_dir}/rpms.in.yaml"

# Verify and commit
git diff rpms.lock.yaml
git add rpms.lock.yaml
git commit -s -S -m "Update rpms.lock.yaml"
git push origin <branch-name>
```
