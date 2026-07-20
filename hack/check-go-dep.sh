#!/bin/bash
# Check if Go packages exist as dependencies across submodules and release branches.
# Accepts multiple packages/CVEs in a single invocation.
#
# Usage:
#   ./hack/check-go-dep.sh golang.org/x/image golang.org/x/net
#   ./hack/check-go-dep.sh CVE-2026-33813 CVE-2024-45338
#   ./hack/check-go-dep.sh CVE-2026-33813 golang.org/x/image
#   ./hack/check-go-dep.sh --branches release-0.14,release-0.15 golang.org/x/net
#   ./hack/check-go-dep.sh --version 0.15 golang.org/x/image
#   ./hack/check-go-dep.sh --acm 2.16.0 golang.org/x/image
#   ./hack/check-go-dep.sh --all golang.org/x/net

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
VERBOSE=false

# ── colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

if [[ ! -t 1 ]]; then
    RED='' GREEN='' YELLOW='' BOLD='' DIM='' RESET=''
fi

# Auto-detect active release branches: those that have .tekton/ on upstream
detect_active_branches() {
    local branches=()
    for branch in $(git -C "$REPO_ROOT" branch -r 2>/dev/null | grep 'upstream/release-' | sed 's|.*upstream/||' | sort -V); do
        if [[ -n "$(git -C "$REPO_ROOT" ls-tree "upstream/${branch}" .tekton/ 2>/dev/null)" ]]; then
            branches+=("$branch")
        fi
    done
    if [[ ${#branches[@]} -gt 0 ]]; then
        echo "${branches[*]}" | tr ' ' ','
    else
        echo "release-0.14,release-0.15,release-0.16"
    fi
}

# Resolve a version input to a release branch name.
# Accepts: "0.15", "0.14.2", "release-0.15", or ACM "2.16.0"
resolve_version_to_branch() {
    local ver="$1"
    # Already a branch name
    if [[ "$ver" =~ ^release- ]]; then
        echo "$ver"
        return
    fi
    local major minor
    major=$(echo "$ver" | cut -d. -f1)
    minor=$(echo "$ver" | cut -d. -f2)
    if [[ "$major" -ge 2 ]]; then
        # ACM version: X.Y.Z → release-(X-2).(Y-1)
        local vs_major=$((major - 2))
        local vs_minor=$((minor - 1))
        if [[ "$vs_major" -lt 0 || "$vs_minor" -lt 0 ]]; then
            die "Cannot map ACM version ${ver} to a VolSync release branch (result: release-${vs_major}.${vs_minor})"
        fi
        echo "release-${vs_major}.${vs_minor}"
    else
        # VolSync version: 0.15 or 0.15.2 → release-0.15
        echo "release-${major}.${minor}"
    fi
}

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

vcmd() { $VERBOSE && echo -e "    $*" || true; }
vout() { $VERBOSE && echo -e "    ${DIM}→ $*${RESET}" || true; }

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

# Stdlib packages have no dot in their first path segment (e.g., crypto/x509, net/http).
is_stdlib_package() {
    local pkg="$1"
    local first_segment="${pkg%%/*}"
    [[ "$first_segment" != *.* ]]
}

# Extract Go toolchain version from go.mod content (stdin).
# Prefers toolchain directive (actual build version) over go directive (minimum version).
extract_go_version() {
    local gomod_content
    gomod_content=$(cat)

    local toolchain_ver
    toolchain_ver=$(echo "$gomod_content" | grep -Po '^toolchain\s+go\K[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
    if [[ -n "$toolchain_ver" ]]; then
        echo "$toolchain_ver"
        return
    fi

    local go_ver
    go_ver=$(echo "$gomod_content" | grep -Po '^go\s+\K[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
    if [[ -n "$go_ver" ]]; then
        echo "$go_ver"
        return
    fi
}

# Extract builder image reference from Dockerfile content.
extract_builder_image_ref() {
    local content="$1"
    echo "$content" | grep -oP 'brew\.registry\.redhat\.io/rh-osbs/openshift-golang-builder:[^\s]+' | head -1
}

# Get Go version from builder image labels via skopeo.
check_builder_image_version() {
    local image_ref="$1"
    command -v skopeo >/dev/null 2>&1 || return 1
    # Strip tag when digest is present: image:tag@sha256:... → image@sha256:...
    if [[ "$image_ref" == *@sha256:* ]]; then
        image_ref="${image_ref%%:*}@${image_ref#*@}"
    fi
    skopeo inspect --config "docker://${image_ref}" 2>/dev/null \
        | jq -r '.config.Labels.version // empty' 2>/dev/null \
        | sed 's/^v//'
}

# Check builder image Go version for a branch (stdlib CVEs only).
# Uses git show to read Dockerfile.rhtap, skopeo to inspect the image.
# Returns via BUILDER_STATUS: "fixed", "vulnerable", or "unknown".
check_builder_for_branch() {
    local branch="$1" pkg="$2"
    BUILDER_STATUS="unknown"
    BUILDER_VER=""
    BUILDER_REF=""

    local dockerfile_content
    dockerfile_content=$(git -C "$REPO_ROOT" show "upstream/${branch}:Dockerfile.rhtap" 2>/dev/null) || return 0

    local builder_ref
    builder_ref=$(extract_builder_image_ref "$dockerfile_content")
    [[ -n "$builder_ref" ]] || return 0
    BUILDER_REF="$builder_ref"

    local builder_ver
    builder_ver=$(check_builder_image_version "$builder_ref") || return 0
    [[ -n "$builder_ver" ]] || return 0

    BUILDER_VER="$builder_ver"
    local assessment
    assessment=$(assess_version "$pkg" "${builder_ver} (builder)")
    if [[ "$assessment" == *"FIXED"* || "$assessment" == *"PATCHED"* ]]; then
        BUILDER_STATUS="fixed"
    elif [[ "$assessment" == *"VULNERABLE"* ]]; then
        BUILDER_STATUS="vulnerable"
    fi
    printf "  %-24s v%s (builder image)%s\n" "Builder image" "$builder_ver" "$assessment"
    # Strip tag when digest is present for the skopeo command (same logic as check_builder_image_version)
    local skopeo_ref="$builder_ref"
    if [[ "$skopeo_ref" == *@sha256:* ]]; then
        skopeo_ref="${skopeo_ref%%:*}@${skopeo_ref#*@}"
    fi
    vcmd "git show upstream/${branch}:Dockerfile.rhtap | grep golang-builder"
    vout "${builder_ref}"
    vcmd "skopeo inspect --config 'docker://${skopeo_ref}' | jq -r '.config.Labels.version'"
    vout "${builder_ver}"
}

# Find the latest version tag for a branch (e.g., v0.14.2 for release-0.14).
# Only matches tags with the same major.minor as the branch name.
find_latest_tag_for_branch() {
    local branch="$1"
    local version_prefix="${branch#release-}"
    git -C "$REPO_ROOT" tag -l "v${version_prefix}.*" --sort=-v:refname --merged "upstream/${branch}" 2>/dev/null | head -1
}

# Check if the fix is shipped (included in the latest release tag).
# For stdlib: compares builder image Go version at the tag vs fix version.
# Sets SHIPPED_STATUS to "shipped", "not_shipped", or "unreleased".
check_shipped_status_stdlib() {
    local branch="$1" pkg="$2"
    SHIPPED_STATUS="unreleased"
    SHIPPED_TAG=""

    local tag
    tag=$(find_latest_tag_for_branch "$branch")
    if [[ -z "$tag" ]]; then
        vcmd "git tag -l 'v${branch#release-}.*' --sort=-v:refname --merged upstream/${branch} | head -1"
        vout "(no tags found)"
        return
    fi
    SHIPPED_TAG="$tag"
    vcmd "git tag -l 'v${branch#release-}.*' --sort=-v:refname --merged upstream/${branch} | head -1"
    vout "${tag}"

    local dockerfile_content
    dockerfile_content=$(git -C "$REPO_ROOT" show "${tag}:Dockerfile.rhtap" 2>/dev/null) || return 0

    local builder_ref
    builder_ref=$(extract_builder_image_ref "$dockerfile_content")
    [[ -n "$builder_ref" ]] || return 0

    local builder_ver
    builder_ver=$(check_builder_image_version "$builder_ref") || return 0
    [[ -n "$builder_ver" ]] || return 0

    local skopeo_ref="$builder_ref"
    if [[ "$skopeo_ref" == *@sha256:* ]]; then
        skopeo_ref="${skopeo_ref%%:*}@${skopeo_ref#*@}"
    fi
    vcmd "git show ${tag}:Dockerfile.rhtap | grep golang-builder"
    vout "${builder_ref}"
    vcmd "skopeo inspect --config 'docker://${skopeo_ref}' | jq -r '.config.Labels.version'"
    vout "${builder_ver}"

    local assessment
    assessment=$(assess_version "$pkg" "${builder_ver} (builder)")
    if [[ "$assessment" == *"FIXED"* || "$assessment" == *"PATCHED"* ]]; then
        SHIPPED_STATUS="shipped"
        vout "${tag} builder Go ${builder_ver} = branch tip Go ${BUILDER_VER} → shipped"
    else
        SHIPPED_STATUS="not_shipped"
        vout "${tag} builder Go ${builder_ver} < branch tip Go ${BUILDER_VER} → not yet shipped"
    fi
}

# Check if a non-stdlib fix is shipped by inspecting the dep version at the latest tag.
# Sets SHIPPED_STATUS to "shipped", "not_shipped", or "unreleased".
check_shipped_status_dep() {
    local branch="$1" pkg="$2"
    SHIPPED_STATUS="unreleased"
    SHIPPED_TAG=""

    local tag
    tag=$(find_latest_tag_for_branch "$branch")
    if [[ -z "$tag" ]]; then
        vcmd "git tag -l 'v${branch#release-}.*' --sort=-v:refname --merged upstream/${branch} | head -1"
        vout "(no tags found)"
        return
    fi
    SHIPPED_TAG="$tag"
    vcmd "git tag -l 'v${branch#release-}.*' --sort=-v:refname --merged upstream/${branch} | head -1"
    vout "${tag}"

    local any_vulnerable=false
    local any_found=false

    for entry in "${SUBMODULE_GOMODS[@]}"; do
        IFS=':' read -r label submod_dir gomod_path <<< "$entry"
        local submod_commit
        submod_commit=$(git -C "$REPO_ROOT" ls-tree "${tag}" "${submod_dir}" 2>/dev/null | awk '{print $3}')
        [[ -n "$submod_commit" ]] || continue
        local gomod_content
        gomod_content=$(git -C "${REPO_ROOT}/${submod_dir}" show "${submod_commit}:${gomod_path}" 2>/dev/null) || continue
        local result
        result=$(echo "$gomod_content" | search_gomod "$pkg")
        [[ -n "$result" ]] || continue
        any_found=true
        local assessment
        assessment=$(assess_version "$pkg" "$result")
        vout "${label} @ ${tag}: ${result}${assessment}"
        if [[ "$assessment" == *"VULNERABLE"* ]]; then
            any_vulnerable=true
        fi
    done

    if ! $any_found; then
        return
    fi

    if $any_vulnerable; then
        SHIPPED_STATUS="not_shipped"
    else
        SHIPPED_STATUS="shipped"
    fi
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

# Classify a single input and add it to the appropriate list.
# Called once per positional argument.
classify_input() {
    local input="$1"

    if [[ "$input" =~ ^https?://.*CVE-[0-9]{4}-[0-9]+ ]]; then
        local cve_id
        cve_id=$(echo "$input" | grep -oP 'CVE-[0-9]{4}-[0-9]+')
        CVE_IDS+=("$cve_id")
    elif [[ "$input" =~ ^CVE-[0-9]{4}-[0-9]+$ ]]; then
        CVE_IDS+=("$input")
    else
        PLAIN_PACKAGES+=("$input")
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
        elif (.version | test("^<=\\s")) then
            # Parse freeform inclusive: "<= 1.79.3" → {version:"0", lessOrEqual:"1.79.3"}
            {
                version: "0",
                lessOrEqual: (.version | gsub("^<=\\s*"; "")),
                status: .status,
                versionType: (.versionType // "semver")
            }
        elif (.version | test("^[<>]=?\\s")) then
            # Parse freeform exclusive: "< 1.79.3" → {version:"0", lessThan:"1.79.3"}
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
    CVE_JSON=$(curl -sf "${CVE_API}/${cve_id}" 2>/dev/null) || die "Failed to fetch ${cve_id} (network error or invalid CVE ID)"

    if ! echo "$CVE_JSON" | jq -e '.' >/dev/null 2>&1; then
        die "Invalid JSON response for ${cve_id}"
    fi

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

        if is_stdlib_package "$pkg_name"; then
            echo "  Note: '${pkg_name}' is a Go stdlib package (bundled with the Go toolchain)"
        elif [[ ! "$pkg_name" =~ / ]]; then
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

    # Extract description and references for verification
    local cve_desc
    cve_desc=$(echo "$CVE_JSON" | jq -r '.containers.cna.descriptions[0].value // empty')

    echo ""
    echo "=== ${cve_id} ==="

    if [[ -n "$cve_desc" ]]; then
        echo "Description: ${cve_desc}"
    fi

    for pkg in "${PACKAGES[@]}"; do
        echo "Package: ${pkg}"
        local ranges="${CVE_RANGES[$pkg]}"
        local num_ranges
        num_ranges=$(echo "$ranges" | jq 'length')
        for j in $(seq 0 $((num_ranges - 1))); do
            local from lt le status
            from=$(echo "$ranges" | jq -r ".[$j].version")
            lt=$(echo "$ranges" | jq -r ".[$j].lessThan // empty")
            le=$(echo "$ranges" | jq -r ".[$j].lessOrEqual // empty")
            status=$(echo "$ranges" | jq -r ".[$j].status")
            if [[ "$status" == "affected" && -n "$lt" ]]; then
                echo "  Affected: [${from}, ${lt})"
            elif [[ "$status" == "affected" && -n "$le" ]]; then
                echo "  Affected: [${from}, ${le}]"
            elif [[ "$status" == "affected" ]]; then
                echo "  Affected: ${from}"
            fi
        done
    done

    # Show references so the user can verify
    local refs
    refs=$(echo "$CVE_JSON" | jq -r '.containers.cna.references[]?.url // empty' 2>/dev/null)
    if [[ -n "$refs" ]]; then
        echo "References:"
        while IFS= read -r url; do
            echo "  - ${url}"
        done <<< "$refs"
    fi
    echo "  - https://www.cve.org/CVERecord?id=${cve_id}"
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
    if [[ "$ver" == "=>" ]]; then
        ver=$(echo "$ver_info" | awk '{print $2}')
    fi
    ver=${ver#go}  # strip "go" prefix for stdlib versions (e.g., go1.25.0 → 1.25.0)
    ver=$(strip_v "$ver")

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
        local from lt le status
        from=$(echo "$ranges" | jq -r ".[$j].version")
        lt=$(echo "$ranges" | jq -r ".[$j].lessThan // empty")
        le=$(echo "$ranges" | jq -r ".[$j].lessOrEqual // empty")
        status=$(echo "$ranges" | jq -r ".[$j].status")

        local affected=false
        if [[ "$status" == "affected" && -n "$lt" ]] && is_version_affected "$ver" "$from" "$lt"; then
            affected=true
        elif [[ "$status" == "affected" && -n "$le" ]]; then
            ver=$(strip_v "$ver"); from=$(strip_v "$from"); le=$(strip_v "$le")
            if version_le "$from" "$ver" && version_le "$ver" "$le"; then
                affected=true
            fi
        fi

        if $affected; then
            printf "  ${RED}⚠ VULNERABLE${RESET}"
            return
        fi
    done

    printf "  ${GREEN}✓ FIXED${RESET}"
}

# ── main ─────────────────────────────────────────────────────────────────────

usage() {
    cat <<'USAGE'
Usage: check-go-dep.sh [OPTIONS] <package-or-cve> [<package-or-cve> ...]

Checks whether Go packages exist as dependencies across submodules and
release branches, including CVE-patches go.mod overrides. Accepts multiple
packages and/or CVEs in a single invocation.

Arguments:
  package-or-cve    Go package name, CVE ID, or CVE URL (one or more)
                    Examples:
                      golang.org/x/image
                      CVE-2026-33813
                      https://www.cve.org/CVERecord?id=CVE-2026-33813

Branch selection (default: auto-detect active branches via .tekton/):
  --version LIST    Comma-separated VolSync or ACM versions
                      VolSync: 0.14, 0.15.2 → release-0.14, release-0.15
                      ACM:     2.16.0       → release-0.15 (X-2, Y-1)
  --branches LIST   Comma-separated release branch names
  --all             Check all upstream/release-* branches

Other options:
  --no-fetch        Skip fetching upstream and submodules
  -v, --verbose     Show evidence (commands + outputs) behind each determination
  -h, --help        Show this help

Workflow:
  This script finds WHERE vulnerable deps are. To determine IF they
  actually matter, follow up with:
    ./hack/cve-triage.sh <CVE-ID>

Example output (package mode):

  --- release-0.15 ---
    volsync                  not found
    rclone                   v0.32.0 (indirect)
    syncthing                not found
    CVE-patch/rclone         v0.32.0 (indirect)

Example output (CVE mode):

  === CVE-2024-45338 ===
  Package: golang.org/x/net/html
    Affected: [0, 0.33.0)

  --- release-0.15 ---
    volsync                  v0.49.0 (indirect)   ✓ FIXED
    rclone                   v0.47.0 (direct)     ✓ FIXED
    CVE-patch/rclone         v0.48.0 (direct)     ✓ FIXED
    Release status           ✓ SHIPPED (v0.15.1)

  If any submodule shows ⚠ VULNERABLE, run:
    ./hack/cve-triage.sh --submodule <name> <CVE-ID>

Example output (CVE mode, stdlib package, builder fixed):

  --- release-0.15 ---
    Builder image            v1.25.9 (builder image)  ✓ FIXED
    Release status           ✓ SHIPPED (v0.15.1)

Example output (CVE mode, stdlib package, builder fixed but not shipped):

  --- release-0.16 ---
    Builder image            v1.25.9 (builder image)  ✓ FIXED
    Release status           ⏳ NOT YET SHIPPED (no release tag found)
USAGE
    exit 0
}

# ── per-input processing ───────────────────────────────────────────────────

# Check a single package against a single go.mod's content.
# Args: input_mode label pkg gomod_content missing_label
#   missing_label: what to print when gomod_content is empty (e.g., "not found (no go.mod)" or "n/a")
check_pkg_in_gomod() {
    local input_mode="$1" label="$2" pkg="$3" gomod_content="$4" missing_label="$5"

    if [[ -z "$gomod_content" ]]; then
        printf "  %-24s ${DIM}%s${RESET}\n" "$label" "$missing_label"
        return
    fi

    if is_stdlib_package "$pkg"; then
        local go_ver
        go_ver=$(echo "$gomod_content" | extract_go_version)
        if [[ -n "$go_ver" ]]; then
            local assessment=""
            if [[ "$input_mode" == "cve" ]]; then
                assessment=$(assess_version "$pkg" "go${go_ver} (stdlib)")
            fi
            printf "  %-24s go%s (stdlib)%s\n" "$label" "$go_ver" "$assessment"
        else
            printf "  %-24s ${DIM}unknown go version${RESET}\n" "$label"
        fi
    else
        local result
        result=$(echo "$gomod_content" | search_gomod "$pkg")

        if [[ -n "$result" ]]; then
            local assessment=""
            if [[ "$input_mode" == "cve" ]]; then
                assessment=$(assess_version "$pkg" "$result")
            fi
            printf "  %-24s %s%s\n" "$label" "$result" "$assessment"
        else
            printf "  %-24s ${DIM}not found${RESET}\n" "$label"
        fi
    fi
}

check_branches_for_packages() {
    local input_mode="$1"
    shift
    local -a pkgs=("$@")

    for branch in "${BRANCHES[@]}"; do
        branch=$(echo "$branch" | xargs)

        if ! git -C "$REPO_ROOT" rev-parse "upstream/${branch}" >/dev/null 2>&1; then
            echo -e "${DIM}--- ${branch} --- (NOT FOUND on upstream, skipping)${RESET}"
            echo ""
            continue
        fi

        echo -e "${BOLD}--- ${branch} ---${RESET}"

        # For stdlib CVEs, check the builder image first — if FIXED, the
        # individual go.mod versions are irrelevant (they're minimums, not
        # the actual compiler version).
        local stdlib_builder_fixed=false
        local is_stdlib_cve=false
        if [[ "$input_mode" == "cve" ]]; then
            for pkg in "${pkgs[@]}"; do
                if is_stdlib_package "$pkg"; then
                    is_stdlib_cve=true
                    check_builder_for_branch "$branch" "$pkg"
                    if [[ "$BUILDER_STATUS" == "fixed" ]]; then
                        stdlib_builder_fixed=true
                        check_shipped_status_stdlib "$branch" "$pkg"
                        case "$SHIPPED_STATUS" in
                            shipped)
                                printf "  %-24s ${GREEN}%s${RESET}\n" "Release status" "✓ SHIPPED (${SHIPPED_TAG})" ;;
                            not_shipped)
                                printf "  %-24s ${YELLOW}%s${RESET}\n" "Release status" "⏳ NOT YET SHIPPED (fix is on branch, latest release is ${SHIPPED_TAG})" ;;
                            unreleased)
                                printf "  %-24s ${YELLOW}%s${RESET}\n" "Release status" "⏳ NOT YET SHIPPED (no release tag found)" ;;
                        esac
                    fi
                    break
                fi
            done
        fi

        if $stdlib_builder_fixed; then
            echo ""
            continue
        fi

        for pkg in "${pkgs[@]}"; do
            if [[ ${#pkgs[@]} -gt 1 ]]; then
                printf "  [%s]\n" "$pkg"
            fi

            for entry in "${SUBMODULE_GOMODS[@]}"; do
                IFS=':' read -r label submod_dir gomod_path <<< "$entry"
                local gomod_content
                gomod_content=$(read_submodule_gomod "$branch" "$submod_dir" "$gomod_path" 2>/dev/null || true)
                check_pkg_in_gomod "$input_mode" "$label" "$pkg" "$gomod_content" "not found (no go.mod)"
            done

            for entry in "${PATCH_GOMODS[@]}"; do
                IFS=':' read -r label path <<< "$entry"
                local gomod_content
                gomod_content=$(read_patch_gomod "$branch" "$path" 2>/dev/null || true)
                check_pkg_in_gomod "$input_mode" "$label" "$pkg" "$gomod_content" "n/a"
            done
        done

        # For non-stdlib CVEs, check shipped status after showing dep versions
        if [[ "$input_mode" == "cve" ]] && ! $is_stdlib_cve; then
            for pkg in "${pkgs[@]}"; do
                check_shipped_status_dep "$branch" "$pkg"
                case "$SHIPPED_STATUS" in
                    shipped)
                        printf "  %-24s ${GREEN}%s${RESET}\n" "Release status" "✓ SHIPPED (${SHIPPED_TAG})" ;;
                    not_shipped)
                        printf "  %-24s ${YELLOW}%s${RESET}\n" "Release status" "⏳ NOT YET SHIPPED (fix is on branch, latest release is ${SHIPPED_TAG})" ;;
                    unreleased)
                        printf "  %-24s ${YELLOW}%s${RESET}\n" "Release status" "⏳ NOT YET SHIPPED (no release tag found)" ;;
                esac
                break
            done
        fi

        echo ""
    done
}


# ── main ─────────────────────────────────────────────────────────────────────

main() {
    check_deps

    local branches_csv=""
    local do_fetch=true
    local -a positionals=()

    CVE_IDS=()
    PLAIN_PACKAGES=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --branches)
                branches_csv="$2"
                shift 2
                ;;
            --version)
                local versions_input="$2"
                local -a resolved=()
                IFS=',' read -ra vers <<< "$versions_input"
                for v in "${vers[@]}"; do
                    resolved+=("$(resolve_version_to_branch "$(echo "$v" | xargs)")")
                done
                branches_csv=$(IFS=','; echo "${resolved[*]}")
                shift 2
                ;;
            --all)
                branches_csv=$(git -C "$REPO_ROOT" branch -r | grep 'upstream/release-' | sed 's|.*upstream/||' | sort -V | tr '\n' ',')
                branches_csv="${branches_csv%,}"
                shift
                ;;
            --acm)
                branches_csv=$(resolve_version_to_branch "$2")
                shift 2
                ;;
            --no-fetch)
                do_fetch=false
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            -*)
                die "Unknown option: $1"
                ;;
            *)
                positionals+=("$1")
                shift
                ;;
        esac
    done

    [[ ${#positionals[@]} -gt 0 ]] || die "Missing argument(s). Run with --help for usage."

    # Classify all inputs
    for arg in "${positionals[@]}"; do
        classify_input "$arg"
    done

    # Resolve default branches if none specified
    if [[ -z "$branches_csv" ]]; then
        branches_csv=$(detect_active_branches)
    fi
    IFS=',' read -ra BRANCHES <<< "$branches_csv"
    echo "Branches: ${BRANCHES[*]}"

    # Fetch upstream and submodules
    if $do_fetch; then
        echo "Fetching upstream and submodules..."
        git -C "$REPO_ROOT" fetch upstream --quiet 2>/dev/null || echo "  Warning: failed to fetch upstream"
        for sub in volsync rclone syncthing diskrsync; do
            git -C "${REPO_ROOT}/${sub}" fetch --quiet 2>/dev/null || true
        done
        echo ""
    fi

    # Process CVE inputs
    for cve_id in "${CVE_IDS[@]}"; do
        INPUT_MODE="cve"
        PACKAGES=()
        declare -g -A CVE_RANGES=()

        fetch_cve_data "$cve_id"
        check_branches_for_packages "cve" "${PACKAGES[@]}"

        # Add stdlib fix guidance
        local has_stdlib=false
        for pkg in "${PACKAGES[@]}"; do
            if is_stdlib_package "$pkg"; then
                has_stdlib=true
                break
            fi
        done

        if $has_stdlib; then
            echo -e "  ${DIM}Note: '${pkg}' is part of the Go standard library.${RESET}"
            echo -e "  ${DIM}Fix: update the Go builder image in the Dockerfile, then rebuild.${RESET}"
            echo -e "  ${DIM}Individual go.mod files do NOT need to be changed.${RESET}"
            echo ""
        fi

        if ! $VERBOSE; then
            echo -e "  ${DIM}Tip: re-run with -v to see the commands and outputs behind each determination.${RESET}"
        fi
        echo ""

        # Suggest follow-up
        echo -e "  Next step: ${BOLD}./hack/cve-triage.sh ${cve_id}${RESET}"
        echo ""
    done

    # Process plain package inputs
    if [[ ${#PLAIN_PACKAGES[@]} -gt 0 ]]; then
        INPUT_MODE="package"
        PACKAGES=("${PLAIN_PACKAGES[@]}")
        check_branches_for_packages "package" "${PACKAGES[@]}"
    fi
}

main "$@"
