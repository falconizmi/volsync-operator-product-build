#!/bin/bash
# Check if a Go package exists as a dependency across submodules and release branches.
#
# Usage:
#   ./hack/check-go-dep.sh golang.org/x/image
#   ./hack/check-go-dep.sh CVE-2026-33813
#   ./hack/check-go-dep.sh https://www.cve.org/CVERecord?id=CVE-2026-33813
#   ./hack/check-go-dep.sh --branches release-0.14,release-0.15 golang.org/x/net
#   ./hack/check-go-dep.sh --acm 2.16.0 golang.org/x/image
#   ./hack/check-go-dep.sh --all golang.org/x/net

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
DEFAULT_BRANCHES="release-0.14,release-0.15,release-0.16"

# Submodules and their go.mod paths (label:submodule_dir:gomod_path_inside_submodule)
SUBMODULE_GOMODS=(
    "volsync:volsync:go.mod"
    "volsync/restic:volsync:mover-restic/restic/go.mod"
    "volsync/minio-go:volsync:mover-restic/minio-go/go.mod"
    "rclone:rclone:go.mod"
    "syncthing:syncthing:go.mod"
    "diskrsync:diskrsync:go.mod"
)

# CVE-patches go.mod paths (label:path_in_tree)
PATCH_GOMODS=(
    "CVE-patch/rclone:CVE-patches/rclone_patch_deps/go.mod"
    "CVE-patch/restic:CVE-patches/restic_patch_deps/restic/go.mod"
    "CVE-patch/minio-go:CVE-patches/restic_patch_deps/minio-go/go.mod"
)

CVE_API="https://cveawg.mitre.org/api/cve"

# ── helpers ──────────────────────────────────────────────────────────────────

die() { echo "ERROR: $*" >&2; exit 1; }

check_deps() {
    for cmd in jq curl git; do
        command -v "$cmd" >/dev/null 2>&1 || die "$cmd is required but not found"
    done
}

# Compare semver: returns 0 if $1 < $2
version_lt() {
    [[ "$1" != "$2" ]] && [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$1" ]]
}

# Compare semver: returns 0 if $1 <= $2
version_le() {
    [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$1" ]]
}

# Strip leading "v" from version string
strip_v() {
    echo "${1#v}"
}

# Check if a version falls in an affected range [from, lessThan)
is_version_affected() {
    local ver="$1" from="$2" less_than="$3"
    ver=$(strip_v "$ver")
    from=$(strip_v "$from")
    less_than=$(strip_v "$less_than")
    version_le "$from" "$ver" && version_lt "$ver" "$less_than"
}

# ── input parsing ────────────────────────────────────────────────────────────

parse_input() {
    local input="$1"

    if [[ "$input" =~ ^https?://.*CVE-[0-9]{4}-[0-9]+ ]]; then
        # CVE URL — extract the CVE ID
        CVE_ID=$(echo "$input" | grep -oP 'CVE-[0-9]{4}-[0-9]+')
        INPUT_MODE="cve"
    elif [[ "$input" =~ ^CVE-[0-9]{4}-[0-9]+$ ]]; then
        CVE_ID="$input"
        INPUT_MODE="cve"
    else
        PACKAGES=("$input")
        INPUT_MODE="package"
    fi
}

# ── CVE API ──────────────────────────────────────────────────────────────────

# Normalize CVE version ranges to a consistent {version, lessThan, status} format.
# Some CVEs use proper {version:"0", lessThan:"1.79.3", status:"affected"}.
# Others use freeform like {version:"< 1.79.3", status:"affected"}.
normalize_version_ranges() {
    local json="$1"
    echo "$json" | jq -c '[.[] |
        if .lessThan then
            .
        elif (.version | test("^[<>]=?\\s")) then
            # Parse freeform: "< 1.79.3" → {version:"0", lessThan:"1.79.3"}
            {
                version: "0",
                lessThan: (.version | gsub("^[<>]=?\\s*"; "")),
                status: .status,
                versionType: (.versionType // "semver")
            }
        else
            .
        end
    ]'
}

fetch_cve_data() {
    local cve_id="$1"
    echo "Fetching ${cve_id} from cveawg.mitre.org..."
    CVE_JSON=$(curl -s "${CVE_API}/${cve_id}")

    if echo "$CVE_JSON" | jq -e '.error' >/dev/null 2>&1; then
        die "CVE API error: $(echo "$CVE_JSON" | jq -r '.error')"
    fi

    local num_affected
    num_affected=$(echo "$CVE_JSON" | jq '.containers.cna.affected | length')
    if [[ "$num_affected" -eq 0 ]]; then
        die "No affected packages found in ${cve_id}"
    fi

    PACKAGES=()
    declare -g -A CVE_RANGES  # key=package, value=JSON array of version ranges

    for i in $(seq 0 $((num_affected - 1))); do
        local pkg_name product_name
        pkg_name=$(echo "$CVE_JSON" | jq -r ".containers.cna.affected[$i].packageName // empty")
        product_name=$(echo "$CVE_JSON" | jq -r ".containers.cna.affected[$i].product // empty")

        # Some CVEs have packageName=null. Fall back to product field.
        if [[ -z "$pkg_name" || "$pkg_name" == "null" ]]; then
            pkg_name="$product_name"
        fi

        # If still no usable module path (e.g., product is "grpc-go" not "google.golang.org/grpc"),
        # warn and skip — user should provide the package name directly.
        if [[ -z "$pkg_name" || "$pkg_name" == "null" ]]; then
            echo "  WARNING: affected[$i] has no packageName or product, skipping"
            continue
        fi

        if [[ ! "$pkg_name" =~ / ]]; then
            echo "  WARNING: '${pkg_name}' does not look like a Go module path."
            echo "           Run again with the actual module path, e.g.:"
            echo "           $0 google.golang.org/grpc"
            echo ""
        fi

        PACKAGES+=("$pkg_name")

        # Normalize version ranges — some CVEs use proper {version, lessThan},
        # others use freeform strings like "< 1.79.3"
        local versions_json
        versions_json=$(echo "$CVE_JSON" | jq -c ".containers.cna.affected[$i].versions")
        versions_json=$(normalize_version_ranges "$versions_json")
        CVE_RANGES["$pkg_name"]="$versions_json"
    done

    echo ""
    echo "=== ${cve_id} ==="
    for pkg in "${PACKAGES[@]}"; do
        echo "Package: ${pkg}"
        local ranges="${CVE_RANGES[$pkg]}"
        local num_ranges
        num_ranges=$(echo "$ranges" | jq 'length')
        for j in $(seq 0 $((num_ranges - 1))); do
            local from lt status
            from=$(echo "$ranges" | jq -r ".[$j].version")
            lt=$(echo "$ranges" | jq -r ".[$j].lessThan // empty")
            status=$(echo "$ranges" | jq -r ".[$j].status")
            if [[ "$status" == "affected" && -n "$lt" ]]; then
                echo "  Affected: [${from}, ${lt})"
            elif [[ "$status" == "affected" ]]; then
                echo "  Affected: ${from}"
            fi
        done
    done
    echo ""
}

# ── go.mod search ────────────────────────────────────────────────────────────

# Search for a package in go.mod content (stdin).
# Handles sub-package → module prefix matching.
# Outputs: "version (direct|indirect)" or "=> version (replace)" or empty
search_gomod() {
    local pkg="$1"
    local gomod_content
    gomod_content=$(cat)

    # Try exact module match first, then strip trailing path segments.
    # Check replace directives first (they override require versions).
    local try="$pkg"
    while [[ -n "$try" ]]; do
        local escaped="${try//./\\.}"
        local match

        # Check replace directives first — these are the effective version
        match=$(echo "$gomod_content" | grep -P "^replace\s+${escaped}\s" 2>/dev/null | head -1 || true)
        if [[ -n "$match" ]]; then
            local replace_ver
            replace_ver=$(echo "$match" | awk '{print $NF}')
            echo "=> ${replace_ver} (replace)"
            return
        fi

        # Check require sections
        match=$(echo "$gomod_content" | grep -P "^\s+${escaped}\s+v" 2>/dev/null | head -1 || true)
        if [[ -n "$match" ]]; then
            local ver type_str
            ver=$(echo "$match" | awk '{print $2}')
            if echo "$match" | grep -q '// indirect'; then
                type_str="indirect"
            else
                type_str="direct"
            fi
            echo "${ver} (${type_str})"
            return
        fi

        # Strip last path segment for sub-package → module matching
        local parent
        parent=$(dirname "$try")
        if [[ "$parent" == "." || "$parent" == "$try" ]]; then
            break
        fi
        try="$parent"
    done
}

# Read a submodule's go.mod at a specific branch
read_submodule_gomod() {
    local branch="$1" submod_dir="$2" gomod_path="$3"

    local submod_commit
    submod_commit=$(git -C "$REPO_ROOT" ls-tree "upstream/${branch}" "${submod_dir}" 2>/dev/null | awk '{print $3}')
    if [[ -z "$submod_commit" ]]; then
        return 1
    fi

    git -C "${REPO_ROOT}/${submod_dir}" show "${submod_commit}:${gomod_path}" 2>/dev/null
}

# Read a CVE-patches go.mod at a specific branch
read_patch_gomod() {
    local branch="$1" path="$2"
    git -C "$REPO_ROOT" show "upstream/${branch}:${path}" 2>/dev/null
}

# ── vulnerability assessment ────────────────────────────────────────────────

assess_version() {
    local pkg="$1" ver_info="$2"

    if [[ "$INPUT_MODE" != "cve" ]]; then
        return
    fi

    local ver
    ver=$(echo "$ver_info" | awk '{print $1}')
    ver=${ver#=>}  # strip replace arrow if present
    ver=$(echo "$ver" | xargs)  # trim whitespace

    if [[ -z "$ver" || "$ver" == "not" ]]; then
        return
    fi

    local ranges="${CVE_RANGES[$pkg]:-}"
    if [[ -z "$ranges" ]]; then
        return
    fi

    local num_ranges
    num_ranges=$(echo "$ranges" | jq 'length')

    for j in $(seq 0 $((num_ranges - 1))); do
        local from lt status
        from=$(echo "$ranges" | jq -r ".[$j].version")
        lt=$(echo "$ranges" | jq -r ".[$j].lessThan")
        status=$(echo "$ranges" | jq -r ".[$j].status")

        if [[ "$status" == "affected" ]] && is_version_affected "$ver" "$from" "$lt"; then
            if echo "$ver_info" | grep -q "(replace)"; then
                printf "  ✓ PATCHED"
            else
                printf "  ⚠ VULNERABLE"
            fi
            return
        fi
    done

    printf "  ✓ FIXED"
}

# ── main ─────────────────────────────────────────────────────────────────────

usage() {
    cat <<'USAGE'
Usage: check-go-dep.sh [OPTIONS] <package-or-cve>

Arguments:
  package-or-cve    Go package name, CVE ID, or CVE URL
                    Examples:
                      golang.org/x/image
                      CVE-2026-33813
                      https://www.cve.org/CVERecord?id=CVE-2026-33813

Options:
  --branches LIST   Comma-separated release branches (default: release-0.14,release-0.15,release-0.16)
  --all             Check all upstream/release-* branches
  --acm VERSION     Convert ACM version to release branch (e.g., 2.16.0 → release-0.15)
  --no-fetch        Skip fetching upstream and submodules
  -h, --help        Show this help
USAGE
    exit 0
}

main() {
    check_deps

    local branches_csv="$DEFAULT_BRANCHES"
    local do_fetch=true
    local positional=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --branches)
                branches_csv="$2"
                shift 2
                ;;
            --all)
                branches_csv=$(git -C "$REPO_ROOT" branch -r | grep 'upstream/release-' | sed 's|.*upstream/||' | sort -V | tr '\n' ',')
                branches_csv="${branches_csv%,}"
                shift
                ;;
            --acm)
                local acm_ver="$2"
                local acm_major acm_minor
                acm_major=$(echo "$acm_ver" | cut -d. -f1)
                acm_minor=$(echo "$acm_ver" | cut -d. -f2)
                branches_csv="release-$((acm_major - 2)).$((acm_minor - 1))"
                shift 2
                ;;
            --no-fetch)
                do_fetch=false
                shift
                ;;
            -h|--help)
                usage
                ;;
            -*)
                die "Unknown option: $1"
                ;;
            *)
                positional="$1"
                shift
                ;;
        esac
    done

    [[ -n "$positional" ]] || die "Missing argument. Run with --help for usage."

    parse_input "$positional"

    # Fetch upstream and submodules
    if $do_fetch; then
        echo "Fetching upstream and submodules..."
        git -C "$REPO_ROOT" fetch upstream --quiet 2>/dev/null || echo "  Warning: failed to fetch upstream"
        for sub in volsync rclone syncthing diskrsync; do
            git -C "${REPO_ROOT}/${sub}" fetch --quiet 2>/dev/null || true
        done
        echo ""
    fi

    # CVE mode: fetch CVE data
    if [[ "$INPUT_MODE" == "cve" ]]; then
        fetch_cve_data "$CVE_ID"
    fi

    # Parse branches
    IFS=',' read -ra BRANCHES <<< "$branches_csv"

    # Check each branch
    for branch in "${BRANCHES[@]}"; do
        branch=$(echo "$branch" | xargs)  # trim whitespace

        # Verify branch exists
        if ! git -C "$REPO_ROOT" rev-parse "upstream/${branch}" >/dev/null 2>&1; then
            echo "--- ${branch} --- (NOT FOUND on upstream, skipping)"
            echo ""
            continue
        fi

        echo "--- ${branch} ---"

        for pkg in "${PACKAGES[@]}"; do
            # Check submodule go.mods
            for entry in "${SUBMODULE_GOMODS[@]}"; do
                IFS=':' read -r label submod_dir gomod_path <<< "$entry"

                local gomod_content result
                gomod_content=$(read_submodule_gomod "$branch" "$submod_dir" "$gomod_path" 2>/dev/null || true)

                if [[ -z "$gomod_content" ]]; then
                    printf "  %-24s not found (no go.mod)\n" "$label"
                    continue
                fi

                result=$(echo "$gomod_content" | search_gomod "$pkg")

                if [[ -n "$result" ]]; then
                    local assessment=""
                    if [[ "$INPUT_MODE" == "cve" ]]; then
                        assessment=$(assess_version "$pkg" "$result")
                    fi
                    printf "  %-24s %s%s\n" "$label" "$result" "$assessment"
                else
                    printf "  %-24s not found\n" "$label"
                fi
            done

            # Check CVE-patches go.mods
            for entry in "${PATCH_GOMODS[@]}"; do
                IFS=':' read -r label path <<< "$entry"

                local gomod_content result
                gomod_content=$(read_patch_gomod "$branch" "$path" 2>/dev/null || true)

                if [[ -z "$gomod_content" ]]; then
                    printf "  %-24s n/a\n" "$label"
                    continue
                fi

                result=$(echo "$gomod_content" | search_gomod "$pkg")

                if [[ -n "$result" ]]; then
                    local assessment=""
                    if [[ "$INPUT_MODE" == "cve" ]]; then
                        assessment=$(assess_version "$pkg" "$result")
                    fi
                    printf "  %-24s %s%s\n" "$label" "$result" "$assessment"
                else
                    printf "  %-24s not found\n" "$label"
                fi
            done
        done

        echo ""
    done
}

main "$@"
