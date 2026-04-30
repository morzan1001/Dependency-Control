#!/usr/bin/env bash

set -euo pipefail

# Configuration & Constants
SCRIPT_VERSION="1.1.0"
TEMP_DIR="${TMPDIR:-/tmp}/dep-control-$$"
AUTH_HEADER=""
readonly MSG_BUILDING_PAYLOAD="Building payload..."
# Mirrors the cap enforced by /api/v1/ingest/cbom; warn before the server
# rejects the upload with 413.
readonly CBOM_MAX_BYTES=$((25 * 1024 * 1024))

# Colors for output (disabled if not a terminal)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    RED='' GREEN='' YELLOW='' BLUE='' NC=''
fi


# Utility Functions
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; return 0; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; return 0; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; return 0; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; return 0; }

cleanup() {
    rm -rf "$TEMP_DIR" 2>/dev/null || true
    return 0
}
trap cleanup EXIT

ensure_deps() {
    local missing=()
    for cmd in "$@"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_info "Installing missing dependencies: ${missing[*]}"

        if [[ -f /etc/alpine-release ]]; then
            apk add --no-cache "${missing[@]}" 2>/dev/null || true
        elif command -v apt-get &> /dev/null; then
            apt-get update -qq && apt-get install -y -qq "${missing[@]}" 2>/dev/null || true
        fi
    fi
    return 0
}

# Environment Detection
detect_ci_environment() {
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        CI_PROVIDER="github"
        PROJECT_NAME="${GITHUB_REPOSITORY:-}"
        BRANCH="${GITHUB_REF_NAME:-}"
        COMMIT_HASH="${GITHUB_SHA:-}"
        PIPELINE_ID="${GITHUB_RUN_ID:-}"
        PIPELINE_IID="${GITHUB_RUN_NUMBER:-}"
        PROJECT_URL="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}"
        PIPELINE_URL="${PROJECT_URL}/actions/runs/${GITHUB_RUN_ID:-}"
        JOB_ID="${GITHUB_RUN_ID:-}"
        JOB_STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        COMMIT_MESSAGE="$(jq -r '.head_commit.message // empty' "$GITHUB_EVENT_PATH" 2>/dev/null || echo "")"
        COMMIT_TAG=""
        [[ "${GITHUB_REF_TYPE:-}" = "tag" ]] && COMMIT_TAG="${GITHUB_REF_NAME:-}"
    elif [[ -n "${GITLAB_CI:-}" ]]; then
        CI_PROVIDER="gitlab"
        PROJECT_NAME="${CI_PROJECT_PATH:-}"
        BRANCH="${CI_COMMIT_REF_NAME:-}"
        COMMIT_HASH="${CI_COMMIT_SHA:-}"
        PIPELINE_ID="${CI_PIPELINE_ID:-}"
        PIPELINE_IID="${CI_PIPELINE_IID:-}"
        PROJECT_URL="${CI_PROJECT_URL:-}"
        PIPELINE_URL="${CI_PIPELINE_URL:-}"
        JOB_ID="${CI_JOB_ID:-}"
        JOB_STARTED_AT="${CI_JOB_STARTED_AT:-}"
        COMMIT_MESSAGE="${CI_COMMIT_MESSAGE:-}"
        COMMIT_TAG="${CI_COMMIT_TAG:-}"
    else
        CI_PROVIDER="local"
        PROJECT_NAME="${PROJECT_NAME:-$(basename "$(pwd)")}"
        BRANCH="${BRANCH:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")}"
        COMMIT_HASH="${COMMIT_HASH:-$(git rev-parse HEAD 2>/dev/null || echo "unknown")}"
        PIPELINE_ID="${PIPELINE_ID:-0}"
        PIPELINE_IID="${PIPELINE_IID:-0}"
        PROJECT_URL="${PROJECT_URL:-}"
        PIPELINE_URL="${PIPELINE_URL:-}"
        JOB_ID="${JOB_ID:-0}"
        JOB_STARTED_AT="${JOB_STARTED_AT:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"
        COMMIT_MESSAGE="${COMMIT_MESSAGE:-}"
        COMMIT_TAG="${COMMIT_TAG:-}"
    fi
    
    log_info "Detected CI provider: $CI_PROVIDER"
    log_info "Project: $PROJECT_NAME | Branch: $BRANCH"
    return 0
}

# Authentication
get_auth_header() {
    if [[ -n "${DEP_CONTROL_API_KEY:-}" ]]; then
        echo "x-api-key: $DEP_CONTROL_API_KEY"
    elif [[ -n "${DEP_CONTROL_TOKEN:-}" ]]; then
        echo "Job-Token: $DEP_CONTROL_TOKEN"
    elif [[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]] && [[ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]]; then
        # GitHub Actions OIDC: request a token from the GitHub OIDC provider
        local audience="${DEP_CONTROL_OIDC_AUDIENCE:-dependency-control}"
        local oidc_url="${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${audience}"
        local oidc_response
        oidc_response=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$oidc_url" 2>/dev/null)
        local oidc_token
        oidc_token=$(echo "$oidc_response" | jq -r '.value // empty' 2>/dev/null)
        if [[ -z "$oidc_token" ]]; then
            log_error "Failed to obtain GitHub Actions OIDC token. Check workflow permissions (id-token: write)."
            exit 1
        fi
        echo "Job-Token: $oidc_token"
    elif [[ -n "${CI_JOB_JWT_V2:-}" ]]; then
        # GitLab CI OIDC token (auto-detected)
        echo "Job-Token: $CI_JOB_JWT_V2"
    else
        log_error "No authentication configured. Set DEP_CONTROL_API_KEY, DEP_CONTROL_TOKEN, or enable OIDC (GitHub Actions: id-token: write, GitLab: CI_JOB_JWT_V2)."
        exit 1
    fi
    return 0
}

# Configuration Check
check_scanner_enabled() {
    local scanner_name="$1"

    log_info "Checking if $scanner_name is enabled..."

    local response http_code config
    response=$(curl -sS --max-time 30 -H "$AUTH_HEADER" -w "\n%{http_code}" \
        "${DEP_CONTROL_URL}/api/v1/ingest/config" 2>/dev/null) || {
        log_warn "Could not reach Dependency Control. Assuming $scanner_name is enabled."
        return 0
    }

    http_code=$(echo "$response" | tail -n1)
    config=$(echo "$response" | sed '$d')

    if [[ "$http_code" -lt 200 ]] || [[ "$http_code" -ge 300 ]]; then
        log_warn "Config check returned HTTP $http_code. Assuming $scanner_name is enabled."
        return 0
    fi

    if echo "$config" | jq -e ".active_analyzers | index(\"$scanner_name\")" > /dev/null 2>&1; then
        log_info "Scanner $scanner_name is enabled."
        return 0
    else
        log_warn "Scanner $scanner_name is disabled. Skipping."
        return 1
    fi
}

# Payload Builder
build_base_payload() {
    local findings_file="${1:-}"
    local findings_key="${2:-findings}"
    local extra_jq="${3:-}"
    
    local jq_args=(
        --arg pn "$PROJECT_NAME"
        --arg br "$BRANCH"
        --arg ch "$COMMIT_HASH"
        --arg pipeline_id "$PIPELINE_ID"
        --arg pipeline_iid "$PIPELINE_IID"
        --arg project_url "$PROJECT_URL"
        --arg pipeline_url "$PIPELINE_URL"
        --arg job_id "$JOB_ID"
        --arg job_started_at "$JOB_STARTED_AT"
        --arg commit_message "$COMMIT_MESSAGE"
        --arg commit_tag "$COMMIT_TAG"
    )
    
    local base_object='{
        project_name: $pn,
        branch: $br,
        commit_hash: $ch,
        pipeline_id: ($pipeline_id | tonumber),
        pipeline_iid: ($pipeline_iid | tonumber),
        project_url: $project_url,
        pipeline_url: $pipeline_url,
        job_id: ($job_id | tonumber),
        job_started_at: $job_started_at,
        commit_message: $commit_message,
        commit_tag: $commit_tag'
    
    if [[ -n "$findings_file" ]] && [[ -f "$findings_file" ]]; then
        jq_args+=(--slurpfile data "$findings_file")
        if [[ -n "$extra_jq" ]]; then
            base_object="${base_object}, ${findings_key}: ${extra_jq}"
        else
            base_object="${base_object}, ${findings_key}: \$data"
        fi
    fi
    
    base_object="${base_object}}"
    
    jq -n "${jq_args[@]}" "$base_object"
    return 0
}

# Upload Function
upload_results() {
    local endpoint="$1"
    local payload_file="$2"
    local fail_on_error="${3:-false}"

    log_info "Uploading results to ${DEP_CONTROL_URL}${endpoint}..."

    local response
    response=$(curl -sS --max-time 120 -X POST \
        -H "Content-Type: application/json" \
        -H "$AUTH_HEADER" \
        -d @"$payload_file" \
        -w "\n%{http_code}" \
        "${DEP_CONTROL_URL}${endpoint}" 2>/dev/null) || {
        log_error "Failed to connect to Dependency Control"
        return 1
    }
    
    local http_code body
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [[ "$http_code" -lt 200 ]] || [[ "$http_code" -ge 300 ]]; then
        log_error "Upload failed with HTTP $http_code: $body"
        return 1
    fi
    
    log_success "Upload successful!"
    echo "$body"
    
    # Check for pipeline failure status (e.g., unwaived secrets)
    if [[ "$fail_on_error" = "true" ]]; then
        local status
        status=$(echo "$body" | jq -r '.status // "success"' 2>/dev/null)
        if [[ "$status" = "failed" ]]; then
            log_error "Pipeline should fail based on scan results!"
            return 1
        fi
    fi
    
    return 0
}

# Scanner: SBOM
scan_sbom() {
    log_info "=== SBOM Generation ==="
    
    mkdir -p "$TEMP_DIR"
    
    # Install Syft if not present
    if ! command -v syft &> /dev/null; then
        log_info "Installing Syft..."
        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
    fi
    
    log_info "Generating SBOM..."
    syft . -o json > "$TEMP_DIR/sbom.json"
    
    log_info "$MSG_BUILDING_PAYLOAD"
    build_base_payload "$TEMP_DIR/sbom.json" "sboms" "\$data" > "$TEMP_DIR/payload.json"
    
    upload_results "/api/v1/ingest" "$TEMP_DIR/payload.json"
    return 0
}

# Scanner: CBOM (CycloneDX cryptographic-asset payload)
#
# Generation is deliberately out of scope: tools like IBM CBOMkit-theia
# (https://github.com/IBM/cbomkit-theia) need either Docker or a Go
# toolchain — too heavy to auto-install in every CI runner. Reference
# pipelines in the dependency-control-pipeline-templates repo handle
# generation; this function only uploads a pre-built CBOM.
scan_cbom() {
    log_info "=== CBOM Upload ==="

    mkdir -p "$TEMP_DIR"

    # Resolve the CBOM file: explicit env var first, then first positional
    # arg, then the conventional names a CycloneDX producer would emit.
    local cbom_file="${CBOM_FILE:-${1:-}}"
    if [[ -z "$cbom_file" ]]; then
        for candidate in cbom.json bom.cbom.json cyclonedx-cbom.json; do
            if [[ -f "$candidate" ]]; then
                cbom_file="$candidate"
                break
            fi
        done
    fi

    if [[ -z "$cbom_file" ]] || [[ ! -f "$cbom_file" ]]; then
        log_warn "No CBOM file found. Set CBOM_FILE or place cbom.json in the working directory."
        log_info "  Generate one with: docker run --rm -v \$(pwd):/src ghcr.io/ibm/cbomkit-theia /src"
        return 0
    fi

    # Reject obvious non-JSON before paying the upload cost.
    if ! jq -e . "$cbom_file" >/dev/null 2>&1; then
        log_error "CBOM file '$cbom_file' is not valid JSON."
        return 1
    fi

    # Body-size cap mirrors /api/v1/ingest/cbom (25 MiB). Stat output
    # differs between BSD and GNU; -c 'size' works on both modern coreutils.
    local size
    size=$(stat -c%s "$cbom_file" 2>/dev/null || stat -f%z "$cbom_file" 2>/dev/null || echo 0)
    if [[ "$size" -gt "$CBOM_MAX_BYTES" ]]; then
        log_error "CBOM file is ${size} bytes; the server limit is ${CBOM_MAX_BYTES} bytes (25 MiB). Aborting upload."
        return 1
    fi

    log_info "Uploading CBOM ($size bytes) from $cbom_file"
    log_info "$MSG_BUILDING_PAYLOAD"

    jq -n \
        --arg pn "$PROJECT_NAME" \
        --arg br "$BRANCH" \
        --arg ch "$COMMIT_HASH" \
        --arg pipeline_id "$PIPELINE_ID" \
        --arg pipeline_iid "$PIPELINE_IID" \
        --arg project_url "$PROJECT_URL" \
        --arg pipeline_url "$PIPELINE_URL" \
        --arg job_id "$JOB_ID" \
        --arg job_started_at "$JOB_STARTED_AT" \
        --arg commit_message "$COMMIT_MESSAGE" \
        --arg commit_tag "$COMMIT_TAG" \
        --slurpfile cbom "$cbom_file" \
        '{
            project_name: $pn,
            branch: $br,
            commit_hash: $ch,
            pipeline_id: ($pipeline_id | tonumber),
            pipeline_iid: ($pipeline_iid | tonumber),
            project_url: $project_url,
            pipeline_url: $pipeline_url,
            job_id: ($job_id | tonumber),
            job_started_at: $job_started_at,
            commit_message: $commit_message,
            commit_tag: $commit_tag,
            cbom: $cbom[0]
        }' > "$TEMP_DIR/cbom_payload.json"

    upload_results "/api/v1/ingest/cbom" "$TEMP_DIR/cbom_payload.json"
}

# Scanner: TruffleHog (Secrets)
scan_secrets() {
    log_info "=== Secret Scan (TruffleHog) ==="
    
    check_scanner_enabled "trufflehog" || return 0
    
    mkdir -p "$TEMP_DIR"
    
    # Install TruffleHog if not present
    if ! command -v trufflehog &> /dev/null; then
        log_info "Installing TruffleHog..."
        curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
    fi
    
    # Ensure full git history for proper scanning
    if [[ -d .git ]]; then
        git fetch --unshallow 2>/dev/null || true
    fi
    
    log_info "Running TruffleHog..."
    trufflehog git file://. --json > "$TEMP_DIR/trufflehog.json" 2>/dev/null || true
    
    log_info "$MSG_BUILDING_PAYLOAD"
    build_base_payload "$TEMP_DIR/trufflehog.json" "findings" "\$data" > "$TEMP_DIR/payload.json"
    
    upload_results "/api/v1/ingest/trufflehog" "$TEMP_DIR/payload.json" "true"
}

# Scanner: OpenGrep/Semgrep (SAST)
scan_sast() {
    log_info "=== SAST Scan (OpenGrep/Semgrep) ==="
    
    check_scanner_enabled "opengrep" || return 0
    
    mkdir -p "$TEMP_DIR"
    
    # Check if semgrep is available (usually run in semgrep container)
    if ! command -v semgrep &> /dev/null; then
        log_warn "Semgrep not installed. This scan should run in the semgrep container."
        log_info "Attempting to install via pip..."
        pip install semgrep --quiet 2>/dev/null || {
            log_error "Could not install semgrep. Skipping SAST scan."
            return 0
        }
    fi
    
    log_info "Running Semgrep..."
    semgrep scan --config=auto --json --output "$TEMP_DIR/opengrep.json" . 2>/dev/null || true
    
    log_info "$MSG_BUILDING_PAYLOAD"
    build_base_payload "$TEMP_DIR/opengrep.json" "findings" "\$data[0].results" > "$TEMP_DIR/payload.json"
    
    upload_results "/api/v1/ingest/opengrep" "$TEMP_DIR/payload.json"
}

# Scanner: KICS (Infrastructure as Code)
scan_iac() {
    log_info "=== IaC Scan (KICS) ==="
    
    check_scanner_enabled "kics" || return 0
    
    mkdir -p "$TEMP_DIR"
    
    # KICS is usually run in the KICS container
    if ! command -v kics &> /dev/null; then
        log_warn "KICS not installed. This scan should run in the KICS container."
        return 0
    fi
    
    log_info "Running KICS..."
    kics scan -p . -o "$TEMP_DIR" --output-name kics-results.json --report-formats json --ignore-on-exit all 2>/dev/null || true
    
    log_info "$MSG_BUILDING_PAYLOAD"
    # KICS has a different output structure
    jq -n \
        --arg pn "$PROJECT_NAME" \
        --arg br "$BRANCH" \
        --arg ch "$COMMIT_HASH" \
        --arg pipeline_id "$PIPELINE_ID" \
        --arg pipeline_iid "$PIPELINE_IID" \
        --arg project_url "$PROJECT_URL" \
        --arg pipeline_url "$PIPELINE_URL" \
        --arg job_id "$JOB_ID" \
        --arg job_started_at "$JOB_STARTED_AT" \
        --arg commit_message "$COMMIT_MESSAGE" \
        --arg commit_tag "$COMMIT_TAG" \
        --slurpfile findings "$TEMP_DIR/kics-results.json" \
        '{
            project_name: $pn,
            branch: $br,
            commit_hash: $ch,
            pipeline_id: ($pipeline_id | tonumber),
            pipeline_iid: ($pipeline_iid | tonumber),
            project_url: $project_url,
            pipeline_url: $pipeline_url,
            job_id: ($job_id | tonumber),
            job_started_at: $job_started_at,
            commit_message: $commit_message,
            commit_tag: $commit_tag,
            queries: $findings[0].queries,
            files: $findings[0].files
        }' > "$TEMP_DIR/payload.json"
    
    upload_results "/api/v1/ingest/kics" "$TEMP_DIR/payload.json"
}

# Scanner: Bearer (Privacy/Security)
scan_bearer() {
    log_info "=== Privacy/Security Scan (Bearer) ==="
    
    check_scanner_enabled "bearer" || return 0
    
    mkdir -p "$TEMP_DIR"
    
    # Install Bearer if not present
    if ! command -v bearer &> /dev/null; then
        log_info "Installing Bearer..."
        curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh -s -- -b /usr/local/bin
    fi
    
    log_info "Running Bearer..."
    bearer scan . --format json --output "$TEMP_DIR/bearer.json" 2>/dev/null || true
    
    log_info "$MSG_BUILDING_PAYLOAD"
    build_base_payload "$TEMP_DIR/bearer.json" "findings" "\$data[0]" > "$TEMP_DIR/payload.json"
    
    upload_results "/api/v1/ingest/bearer" "$TEMP_DIR/payload.json"
}

# Scanner: Callgraph (Reachability)

# Convert a DOT file to JSON (shared by Python and Go generators)
_dot_to_json() {
    local dot_file="$1"
    local json_file="$2"
    python3 << PYTHON_EOF
import re, json, sys
try:
    with open('${dot_file}', 'r') as f:
        content = f.read()
    edges = []
    nodes = set()
    for match in re.finditer(r'"([^"]+)"\\s*->\\s*"([^"]+)"', content):
        source, target = match.groups()
        edges.append({'source': source, 'target': target})
        nodes.add(source)
        nodes.add(target)
    with open('${json_file}', 'w') as f:
        json.dump({'nodes': list(nodes), 'edges': edges}, f)
except Exception as e:
    print(f"Error converting DOT to JSON: {e}", file=sys.stderr)
    with open('${json_file}', 'w') as f:
        json.dump({'nodes': [], 'edges': []}, f)
PYTHON_EOF
}

# Build payload and upload a single callgraph
_upload_callgraph() {
    local project_id="$1"
    local lang="$2"
    local format="$3"
    local json_file="$4"

    if [[ ! -f "$json_file" ]] || [[ ! -s "$json_file" ]]; then
        log_warn "No callgraph generated for $lang. Skipping."
        return 1
    fi

    # Verify callgraph has actual data (not just empty structures)
    # madge format: {"file.js": ["dep.js"]} — check for any keys
    # pyan/generic format: {"nodes": [...], "edges": [...]} — check for non-empty nodes
    if ! jq -e 'if has("nodes") then (.nodes | length > 0) else (keys | length > 0) end' "$json_file" >/dev/null 2>&1; then
        log_warn "Callgraph for $lang is empty (no data). Skipping upload."
        return 1
    fi

    log_info "Uploading $lang callgraph..."
    jq -n \
        --arg format "$format" \
        --arg lang "$lang" \
        --argjson pipeline_id "$PIPELINE_ID" \
        --arg branch "$BRANCH" \
        --arg commit "$COMMIT_HASH" \
        --slurpfile graph "$json_file" \
        '{
            format: $format,
            language: $lang,
            pipeline_id: $pipeline_id,
            branch: $branch,
            commit_hash: $commit,
            data: $graph[0]
        }' > "$TEMP_DIR/callgraph_payload_${lang}.json"

    upload_results "/api/v1/projects/${project_id}/callgraph" "$TEMP_DIR/callgraph_payload_${lang}.json"
}

# Generate callgraph for JavaScript/TypeScript
_generate_callgraph_js() {
    local lang="javascript"
    [[ -f "tsconfig.json" ]] && lang="typescript"

    if ! command -v madge &> /dev/null; then
        npm install -g madge >/dev/null 2>&1 || true
    fi

    local src_dir="."
    [[ -d "lib" ]] && src_dir="lib"
    [[ -d "src" ]] && src_dir="src"

    if [[ "$lang" = "typescript" ]]; then
        madge --json --ts-config tsconfig.json "$src_dir" > "$TEMP_DIR/callgraph_js.json" 2>/dev/null || \
        madge --json "$src_dir" > "$TEMP_DIR/callgraph_js.json" 2>/dev/null || true
    else
        madge --json "$src_dir" > "$TEMP_DIR/callgraph_js.json" 2>/dev/null || true
    fi

    echo "$lang:madge:$TEMP_DIR/callgraph_js.json"
}

# Generate callgraph for Python
_generate_callgraph_python() {
    pip install pyan3 --quiet >/dev/null 2>&1 || true

    find . -name "*.py" -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/node_modules/*" > "$TEMP_DIR/python_files.txt"

    if [[ -s "$TEMP_DIR/python_files.txt" ]]; then
        xargs pyan3 --dot --grouped < "$TEMP_DIR/python_files.txt" > "$TEMP_DIR/callgraph_python.dot" 2>/dev/null || true
        _dot_to_json "$TEMP_DIR/callgraph_python.dot" "$TEMP_DIR/callgraph_python.json"
    fi

    echo "python:pyan:$TEMP_DIR/callgraph_python.json"
}

# Generate callgraph for Go
_generate_callgraph_go() {
    go install github.com/ondrajz/go-callvis@latest >/dev/null 2>&1 || true

    local module_name
    module_name=$(head -1 go.mod | awk '{print $2}')

    "$(go env GOPATH)/bin/go-callvis" -nostd -format=dot "$module_name" > "$TEMP_DIR/callgraph_go.dot" 2>/dev/null || true
    _dot_to_json "$TEMP_DIR/callgraph_go.dot" "$TEMP_DIR/callgraph_go.json"

    echo "go:generic:$TEMP_DIR/callgraph_go.json"
}

scan_callgraph() {
    log_info "=== Callgraph Generation ==="

    check_scanner_enabled "reachability" || return 0

    mkdir -p "$TEMP_DIR"

    # Detect all languages present in the repo
    local detected=()

    if [[ -f "package.json" ]]; then
        detected+=("js")
    fi
    if [[ -f "requirements.txt" ]] || [[ -f "pyproject.toml" ]] || [[ -f "setup.py" ]] || [[ -f "setup.cfg" ]]; then
        detected+=("python")
    fi
    if [[ -f "go.mod" ]]; then
        detected+=("go")
    fi

    if [[ ${#detected[@]} -eq 0 ]]; then
        log_warn "Could not detect any supported language. Skipping callgraph generation."
        return 0
    fi

    log_info "Detected languages: ${detected[*]}"

    # Resolve project ID once
    local project_info project_id encoded_name
    encoded_name=$(printf '%s' "$PROJECT_NAME" | jq -sRr @uri)
    project_info=$(curl -sS -H "$AUTH_HEADER" "${DEP_CONTROL_URL}/api/v1/projects?name=${encoded_name}" 2>/dev/null)
    project_id=$(echo "$project_info" | jq -r '.[0]._id // empty')

    if [[ -z "$project_id" ]]; then
        log_warn "Project not found in Dependency Control. Skipping callgraph upload."
        return 0
    fi

    # Generate and upload callgraph for each detected language
    local uploaded=0

    for lang_key in "${detected[@]}"; do
        local result=""
        case "$lang_key" in
            js)     result=$(_generate_callgraph_js) ;;
            python) result=$(_generate_callgraph_python) ;;
            go)     result=$(_generate_callgraph_go) ;;
        esac

        if [[ -n "$result" ]]; then
            local lang format json_file
            lang=$(echo "$result" | cut -d: -f1)
            format=$(echo "$result" | cut -d: -f2)
            json_file=$(echo "$result" | cut -d: -f3-)

            if _upload_callgraph "$project_id" "$lang" "$format" "$json_file"; then
                uploaded=$((uploaded + 1))
            fi
        fi
    done

    if [[ $uploaded -eq 0 ]]; then
        log_warn "No callgraphs were uploaded."
    else
        log_info "Uploaded $uploaded callgraph(s) for: ${detected[*]}"
    fi
}

# Run All Scans
run_all() {
    log_info "=== Running All Scans ==="
    
    local failed=0
    
    scan_sbom || failed=$((failed + 1))
    # CBOM upload is only attempted when the user supplied a file —
    # generation lives in dedicated pipeline templates, so there's
    # nothing for `all` to do without one.
    if [[ -n "${CBOM_FILE:-}" ]]; then
        scan_cbom || failed=$((failed + 1))
    fi
    scan_secrets || failed=$((failed + 1))
    scan_sast || failed=$((failed + 1))
    scan_iac || failed=$((failed + 1))
    scan_bearer || failed=$((failed + 1))
    scan_callgraph || failed=$((failed + 1))
    
    if [[ $failed -gt 0 ]]; then
        log_warn "$failed scan(s) had issues"
    fi

    log_success "All scans completed!"
    return 0
}

# Main Entry Point
show_help() {
    cat << EOF
Dependency Control Scanner v${SCRIPT_VERSION}

Usage: $0 <command> [options]

Commands:
  sbom        Generate and upload SBOM using Syft
  cbom        Upload a pre-built CycloneDX 1.6 CBOM
  secrets     Run TruffleHog secret scan
  sast        Run OpenGrep/Semgrep SAST scan
  iac         Run KICS Infrastructure-as-Code scan
  bearer      Run Bearer privacy/security scan
  callgraph   Generate and upload callgraph for reachability analysis
  all         Run all enabled scans (CBOM upload runs only when CBOM_FILE is set)

Environment Variables:
  DEP_CONTROL_URL            URL of the Dependency Control instance (required)
  DEP_CONTROL_API_KEY        API Key for authentication
  DEP_CONTROL_TOKEN          OIDC Token for authentication (GitLab/GitHub)
  DEP_CONTROL_OIDC_AUDIENCE  OIDC audience claim (default: "dependency-control")
  CBOM_FILE                  Path to a pre-built CBOM JSON (used by 'cbom' / 'all')

Authentication (checked in order):
  1. DEP_CONTROL_API_KEY          - Project API key (any CI provider)
  2. DEP_CONTROL_TOKEN            - Explicit OIDC/Job token
  3. GitHub Actions OIDC          - Auto-detected via ACTIONS_ID_TOKEN_REQUEST_URL
  4. GitLab CI OIDC               - Auto-detected via CI_JOB_JWT_V2

Examples:
  # Run SBOM scan
  DEP_CONTROL_URL=https://depcontrol.local DEP_CONTROL_API_KEY=xxx $0 sbom

  # Run all scans in GitHub Actions
  $0 all

  # Pipe from backend, pinned to a frozen release (recommended)
  SCANNER_VERSION="${SCRIPT_VERSION}"
  SCANNER_SHA256="<hash from /api/v1/scripts manifest>"
  curl -sSfL "\$DEP_CONTROL_URL/api/v1/scripts/scanner.sh?v=\$SCANNER_VERSION" -o scanner.sh
  echo "\$SCANNER_SHA256  scanner.sh" | sha256sum -c -
  bash scanner.sh all
EOF
    return 0
}

main() {
    local command="${1:-help}"
    
    # Validate required environment
    if [[ "$command" != "help" ]] && [[ "$command" != "--help" ]] && [[ "$command" != "-h" ]] \
        && [[ "$command" != "version" ]] && [[ "$command" != "--version" ]] && [[ "$command" != "-v" ]]; then
        if [[ -z "${DEP_CONTROL_URL:-}" ]]; then
            log_error "DEP_CONTROL_URL environment variable is required"
            exit 1
        fi
        
        # Ensure basic dependencies
        ensure_deps curl jq
        
        # Detect CI environment
        detect_ci_environment

        # Authenticate once (reused by all scan functions)
        AUTH_HEADER="$(get_auth_header)"
    fi
    
    case "$command" in
        sbom)
            scan_sbom
            ;;
        cbom)
            scan_cbom "${2:-}"
            ;;
        secrets)
            scan_secrets
            ;;
        sast)
            scan_sast
            ;;
        iac)
            scan_iac
            ;;
        bearer)
            scan_bearer
            ;;
        callgraph)
            scan_callgraph
            ;;
        all)
            run_all
            ;;
        help|--help|-h)
            show_help
            ;;
        version|--version|-v)
            echo "Dependency Control Scanner v${SCRIPT_VERSION}"
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
    return 0
}

# Export TEMP_DIR for Python scripts
export TEMP_DIR

main "$@"
