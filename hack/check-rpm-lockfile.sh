#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
UPSTREAM_REMOTE="upstream"
GH_REPO="stolostron/volsync-operator-product-build"
RPM_IMAGE="localhost/rpm-lockfile-prototype:latest"
CONTAINER_DIR="/work"
TMPBASE=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Check if rpms.lock.yaml is up-to-date on active release branches and open PRs.

Options:
  --releases-only   Only check active release branches (with .tekton/ pipelines)
  --prs-only        Only check open PR branches
  --branches LIST   Comma-separated list of branches to check (skips discovery)
  --fetch           Run git fetch upstream before checking (default: use cached state)
  --help            Show this help

Examples:
  $(basename "$0")                          # Check all (releases + open PRs)
  $(basename "$0") --releases-only          # Only active release branches
  $(basename "$0") --prs-only              # Only open PR branches
  $(basename "$0") --branches release-0.16  # Specific branch
  $(basename "$0") --fetch                  # Fetch upstream first
EOF
    exit 0
}

# --- Argument parsing ---
MODE="all"
EXPLICIT_BRANCHES=""
DO_FETCH=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --releases-only) MODE="releases" ;;
        --prs-only) MODE="prs" ;;
        --branches)
            MODE="explicit"
            EXPLICIT_BRANCHES="$2"
            shift
            ;;
        --fetch) DO_FETCH=true ;;
        --help) usage ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
    shift
done

# --- Cleanup ---
cleanup() {
    if [[ -n "${TMPBASE}" && -d "${TMPBASE}" ]]; then
        rm -rf "${TMPBASE}"
    fi
}

trap cleanup EXIT INT TERM

# --- Preflight checks ---
preflight() {
    local ok=true

    if ! command -v podman &>/dev/null; then
        echo -e "${RED}ERROR: podman not found.${NC}"
        ok=false
    fi

    if [[ ! -f "$HOME/.docker/config.json" ]]; then
        echo -e "${RED}ERROR: ~/.docker/config.json not found.${NC}"
        echo "  registry.redhat.io access is required. See README.md 'Editing RPM dependencies'."
        ok=false
    fi

    if ! git remote get-url "${UPSTREAM_REMOTE}" &>/dev/null; then
        echo -e "${RED}ERROR: git remote '${UPSTREAM_REMOTE}' not configured.${NC}"
        ok=false
    fi

    if [[ "$MODE" == "prs" || "$MODE" == "all" ]]; then
        if ! command -v gh &>/dev/null; then
            echo -e "${RED}ERROR: gh (GitHub CLI) not found.${NC}"
            ok=false
        elif ! gh auth status &>/dev/null 2>&1; then
            echo -e "${RED}ERROR: gh not authenticated. Run 'gh auth login'.${NC}"
            ok=false
        fi
    fi

    if ! podman image exists "${RPM_IMAGE}" 2>/dev/null; then
        echo -e "${YELLOW}rpm-lockfile-prototype image not found. Building from Containerfile...${NC}"
        if [[ -f "${REPO_ROOT}/Containerfile" ]]; then
            podman build -t "${RPM_IMAGE}" -f "${REPO_ROOT}/Containerfile" "${REPO_ROOT}" || {
                echo -e "${RED}ERROR: Failed to build rpm-lockfile-prototype image.${NC}"
                ok=false
            }
        else
            echo -e "${RED}ERROR: Containerfile not found at ${REPO_ROOT}/Containerfile${NC}"
            echo "  Build manually: podman build -t ${RPM_IMAGE} -f Containerfile ."
            echo "  Or: curl https://raw.githubusercontent.com/konflux-ci/rpm-lockfile-prototype/refs/heads/main/Containerfile | podman build -t ${RPM_IMAGE} -"
            ok=false
        fi
    fi

    if [[ "$ok" != "true" ]]; then
        exit 1
    fi
}

# --- Branch discovery ---
discover_release_branches() {
    local branches=()
    while IFS= read -r ref; do
        local branch="${ref#refs/remotes/${UPSTREAM_REMOTE}/}"
        if git ls-tree --name-only "${ref}" .tekton/ 2>/dev/null | grep -q . &&
           git show "${ref}:rpms.lock.yaml" &>/dev/null 2>&1; then
            branches+=("${branch}")
        fi
    done < <(git for-each-ref --format='%(refname)' "refs/remotes/${UPSTREAM_REMOTE}/release-*" | grep -v '/release-.*/')
    printf '%s\n' "${branches[@]}"
}

discover_pr_branches() {
    local pr_branches=()
    while IFS=$'\t' read -r _number head_branch _rest; do
        local ref="${UPSTREAM_REMOTE}/${head_branch}"
        if git show "${ref}:rpms.lock.yaml" &>/dev/null 2>&1; then
            pr_branches+=("${head_branch}")
        fi
    done < <(gh pr list --repo "${GH_REPO}" --state open --limit 200 --json number,headRefName --jq '.[] | [.number, .headRefName] | @tsv')
    printf '%s\n' "${pr_branches[@]}"
}

collect_branches() {
    local -A seen
    local branches=()

    if [[ "$MODE" == "explicit" ]]; then
        IFS=',' read -ra parts <<< "$EXPLICIT_BRANCHES"
        for b in "${parts[@]}"; do
            branches+=("$(echo "$b" | xargs)")
        done
    else
        if [[ "$MODE" == "all" || "$MODE" == "releases" ]]; then
            while IFS= read -r b; do
                [[ -n "$b" ]] && branches+=("$b") && seen["$b"]=1
            done < <(discover_release_branches)
        fi
        if [[ "$MODE" == "all" || "$MODE" == "prs" ]]; then
            while IFS= read -r b; do
                if [[ -n "$b" && -z "${seen[$b]:-}" ]]; then
                    branches+=("$b")
                    seen["$b"]=1
                fi
            done < <(discover_pr_branches)
        fi
    fi

    printf '%s\n' "${branches[@]}"
}

# --- Per-branch check ---
# Extracts only the files the tool needs (rpms.in.yaml, Dockerfile.rhtap) via
# git-show into a temp directory. No worktree or submodule checkout required.
check_branch() {
    local branch="$1"
    local ref="${UPSTREAM_REMOTE}/${branch}"
    local tmpdir="${TMPBASE}/${branch//\//_}"

    if ! git show "${ref}:rpms.lock.yaml" &>/dev/null 2>&1; then
        echo -e "  ${YELLOW}SKIP${NC} — no rpms.lock.yaml on this branch"
        return 2
    fi

    mkdir -p "${tmpdir}"

    echo -e "  Extracting files..."
    git show "${ref}:rpms.in.yaml" > "${tmpdir}/rpms.in.yaml" 2>/dev/null || {
        echo -e "  ${RED}FAIL${NC} — could not read rpms.in.yaml"
        return 1
    }
    git show "${ref}:rpms.lock.yaml" > "${tmpdir}/rpms.lock.yaml" 2>/dev/null || {
        echo -e "  ${RED}FAIL${NC} — could not read rpms.lock.yaml"
        return 1
    }
    # Dockerfile.rhtap is used by the tool as context for the base image
    git show "${ref}:Dockerfile.rhtap" > "${tmpdir}/Dockerfile.rhtap" 2>/dev/null || true

    echo -e "  Running rpm-lockfile-prototype..."
    if ! podman run --rm \
        -v "${tmpdir}:${CONTAINER_DIR}:z" \
        -v "$HOME/.docker/config.json:/root/.docker/config.json:ro,z" \
        "${RPM_IMAGE}" \
        --outfile="${CONTAINER_DIR}/rpms.lock.yaml" \
        "${CONTAINER_DIR}/rpms.in.yaml" >/dev/null 2>&1; then
        echo -e "  ${RED}FAIL${NC} — rpm-lockfile-prototype failed"
        return 1
    fi

    # Compare the regenerated lockfile against the original
    local original
    original=$(git show "${ref}:rpms.lock.yaml" 2>/dev/null)
    local regenerated
    regenerated=$(cat "${tmpdir}/rpms.lock.yaml")

    if [[ "$original" == "$regenerated" ]]; then
        echo -e "  ${GREEN}UP-TO-DATE${NC}"
        return 0
    else
        echo -e "  ${RED}NEEDS UPDATE${NC}"
        diff <(echo "$original") <(echo "$regenerated") --unified=0 | head -20 || true
        return 3
    fi
}

# --- Main ---
main() {
    echo -e "${BOLD}RPM Lockfile Check${NC}"
    echo ""

    preflight

    TMPBASE=$(mktemp -d)

    if [[ "$DO_FETCH" == "true" ]]; then
        echo -e "${CYAN}Fetching ${UPSTREAM_REMOTE}...${NC}"
        git fetch "${UPSTREAM_REMOTE}" 2>/dev/null
        echo ""
    fi

    mapfile -t branches < <(collect_branches)

    if [[ ${#branches[@]} -eq 0 ]]; then
        echo "No branches found to check."
        exit 0
    fi

    echo -e "${BOLD}Checking ${#branches[@]} branch(es):${NC}"
    echo ""

    local needs_update=()
    local up_to_date=()
    local failed=()

    for branch in "${branches[@]}"; do
        echo -e "${CYAN}${branch}${NC}"
        local rc=0
        check_branch "$branch" || rc=$?
        echo ""

        case $rc in
            0) up_to_date+=("$branch") ;;
            3) needs_update+=("$branch") ;;
            2) ;; # skipped
            *) failed+=("$branch") ;;
        esac
    done

    # Summary
    echo -e "${BOLD}=== Summary ===${NC}"
    echo ""
    if [[ ${#up_to_date[@]} -gt 0 ]]; then
        for b in "${up_to_date[@]}"; do
            echo -e "  ${GREEN}✓${NC} ${b}"
        done
    fi
    if [[ ${#needs_update[@]} -gt 0 ]]; then
        for b in "${needs_update[@]}"; do
            echo -e "  ${RED}✗${NC} ${b}"
        done
    fi
    if [[ ${#failed[@]} -gt 0 ]]; then
        for b in "${failed[@]}"; do
            echo -e "  ${YELLOW}?${NC} ${b}"
        done
    fi
    echo ""

    if [[ ${#needs_update[@]} -gt 0 ]]; then
        echo -e "${YELLOW}${#needs_update[@]} branch(es) need RPM lockfile updates.${NC}"
        exit 1
    else
        echo -e "${GREEN}All branches are up-to-date.${NC}"
    fi
}

main "$@"
