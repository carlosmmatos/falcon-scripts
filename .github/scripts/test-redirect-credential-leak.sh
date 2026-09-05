#!/bin/bash

# Live two-port 307 capture for the shipped OAuth POST and fetch_tags login
# curls. A secret that reaches hop 2 is a failure. The mock is fail-closed:
# an unpinned control request must leak, or the harness itself is broken.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work_dir=$(mktemp -d)
server_pids=""

cleanup() {
    for pid in $server_pids; do
        kill "$pid" 2>/dev/null || true
    done
    rm -rf "$work_dir"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

python_bin=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        python_bin=$candidate
        break
    fi
done
[ -n "$python_bin" ] || fail 'no python interpreter is available for the capture server'

server_script="$work_dir/capture_server.py"
cat >"$server_script" <<'PY'
import sys

try:
    from http.server import BaseHTTPRequestHandler, HTTPServer
except ImportError:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

output_path = sys.argv[1]
redirect_to = sys.argv[2] if len(sys.argv) > 2 else ""


class Handler(BaseHTTPRequestHandler):
    def _capture(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        try:
            body_text = body.decode("utf-8")
        except UnicodeDecodeError:
            body_text = repr(body)
        with open(output_path, "w") as handle:
            handle.write("REQUEST_ARRIVED|auth=[%s]|body=[%s]"
                         % (self.headers.get("Authorization", ""), body_text))

    def _respond(self):
        if redirect_to:
            self.send_response(307)
            self.send_header("Location", redirect_to)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"access_token":"mock","token":"mock"}')

    def do_GET(self):
        self._capture()
        self._respond()

    def do_POST(self):
        self._capture()
        self._respond()

    def log_message(self, *args):
        pass


HTTPServer.allow_reuse_address = True
server = HTTPServer(("127.0.0.1", 0), Handler)
port = server.server_address[1]
with open(output_path + ".port", "w") as handle:
    handle.write(str(port))
with open(output_path + ".ready", "w") as handle:
    handle.write("ready")
server.timeout = 20
server.handle_request()
PY

start_server() {
    output=$1
    redirect_to=${2:-}

    rm -f "$output" "$output.ready" "$output.port"
    "$python_bin" "$server_script" "$output" "$redirect_to" &
    server_pids="$server_pids $!"
}

wait_for_server() {
    output=$1
    attempt=0

    while [ "$attempt" -lt 15 ]; do
        if [ -f "$output.ready" ] && [ -f "$output.port" ]; then
            return 0
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    fail "the capture server for $output did not start"
}

start_redirect_pair() {
    hop1=$1
    hop2=$2
    hop2_path=$3

    start_server "$hop2"
    wait_for_server "$hop2"
    hop2_port=$(cat "$hop2.port")
    start_server "$hop1" "http://127.0.0.1:${hop2_port}${hop2_path}"
    wait_for_server "$hop1"
    hop1_port=$(cat "$hop1.port")
}

assert_hop2_has_secret() {
    file=$1
    secret=$2
    description=$3

    [ -s "$file" ] || fail "$description (no request reached hop 2)"
    grep -qF "$secret" "$file" ||
        fail "$description (hop 2 did not see $secret; capture: $(cat "$file"))"
}

# 1. Control: unpinned curl -L POST must leak, or later "no leak" results are
#    fail-open (the mock never captured a follow).
start_redirect_pair "$work_dir/ctrl1" "$work_dir/ctrl2" "/oauth2/token"
echo "client_id=id&client_secret=REGRESSION_SECRET" |
    curl --silent --show-error -X POST -L \
        "http://127.0.0.1:$(cat "$work_dir/ctrl1.port")/oauth2/token" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data @- >/dev/null
assert_hop2_has_secret "$work_dir/ctrl2" "REGRESSION_SECRET" \
    'control: unpinned oauth POST did not leak to hop 2 (mock is broken)'
echo "control: unpinned oauth POST leaked to hop 2 (mock can detect CAND-001)"

# 2. Control: --proto-redir '=https' must stop the HTTP hop-2 follow.
start_redirect_pair "$work_dir/pin1" "$work_dir/pin2" "/oauth2/token"
set +e
echo "client_id=id&client_secret=REGRESSION_SECRET" |
    curl --silent --show-error -X POST -L --proto-redir '=https' \
        "http://127.0.0.1:$(cat "$work_dir/pin1.port")/oauth2/token" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data @- >/dev/null
set -e
if [ -s "$work_dir/pin2" ] && grep -qF 'REGRESSION_SECRET' "$work_dir/pin2"; then
    fail 'control: --proto-redir =https still delivered the secret to hop 2'
fi
echo "control: --proto-redir =https kept REGRESSION_SECRET off hop 2"

replay_recorded_curl() {
    local args_file=$1 stdin_file=$2 url=$3
    local replay_args=() skip_next="" arg

    while IFS= read -r arg; do
        if [ -n "$skip_next" ]; then
            skip_next=""
            continue
        fi
        case $arg in
            -x)
                skip_next=yes
                continue
                ;;
            --dump-header)
                skip_next=yes
                continue
                ;;
            https://* | http://*)
                replay_args+=("$url")
                continue
                ;;
        esac
        replay_args+=("$arg")
    done <"$args_file"

    set +e
    curl --silent --show-error "${replay_args[@]}" <"$stdin_file" >/dev/null
    set -e
}

record_oauth_from_function() {
    local script=$1
    local helper

    helper=$(awk '/^get_oauth_token\(\)/,/^}/' "$repo_root/$script")
    [ -n "$helper" ] || fail "get_oauth_token not found in $script"

    : >"$work_dir/oauth-args"
    : >"$work_dir/oauth-stdin"

    (
        curl() {
            printf '%s\n' "$@" >"$work_dir/oauth-args"
            cat >"$work_dir/oauth-stdin"
            prev=""
            for arg in "$@"; do
                if [ "$prev" = "--dump-header" ]; then
                    printf 'x-cs-region: us-1\r\n' >"$arg"
                fi
                prev=$arg
            done
            echo '{"access_token":"mock-access-token"}'
        }
        get_falcon_credentials() {
            cs_falcon_client_id="regression-client-id"
            cs_falcon_client_secret="REGRESSION_SECRET"
            cs_falcon_member_cid=""
        }
        cs_cloud() { echo "api.example.invalid"; }
        get_user_agent() { echo "crowdstrike-falcon-scripts/test"; }
        handle_curl_error() { :; }
        json_value() { cat >/dev/null; echo "mock-access-token"; }
        die() { echo "die: $*" >&2; exit 1; }
        proxy=""
        response_headers="$work_dir/oauth-headers"
        printf 'x-cs-region: us-1\r\n' >"$response_headers"
        FALCON_ACCESS_TOKEN=""
        FALCON_CLOUD=us-1
        eval "$helper"
        get_oauth_token
    )
}

record_oauth_from_container() {
    local script=$1
    local block

    block=$(awk '
        /token_result=\$\(echo "client_id=\$FALCON_CLIENT_ID/ { p = 1 }
        p { print }
        /handle_curl_error \$\?/ { if (p) exit }
    ' "$repo_root/$script")
    [ -n "$block" ] || fail "oauth token curl block not found in $script"

    : >"$work_dir/oauth-args"
    : >"$work_dir/oauth-stdin"

    (
        curl() {
            printf '%s\n' "$@" >"$work_dir/oauth-args"
            cat >"$work_dir/oauth-stdin"
            prev=""
            for arg in "$@"; do
                if [ "$prev" = "--dump-header" ]; then
                    printf 'x-cs-region: us-1\r\n' >"$arg"
                fi
                prev=$arg
            done
            echo '{"access_token":"mock-access-token"}'
        }
        cs_cloud() { echo "api.example.invalid"; }
        handle_curl_error() { :; }
        FALCON_CLIENT_ID="regression-client-id"
        FALCON_CLIENT_SECRET="REGRESSION_SECRET"
        VERSION="test"
        response_headers="$work_dir/oauth-headers"
        : >"$response_headers"
        eval "$block"
    )
}

oauth_failures=0

test_shipped_oauth_redirect() {
    local script=$1
    local mode=$2

    if [ "$mode" = "function" ]; then
        record_oauth_from_function "$script"
    else
        record_oauth_from_container "$script"
    fi

    echo "recorded oauth argv for $script:"
    tr '\n' ' ' <"$work_dir/oauth-args"
    echo

    start_redirect_pair "$work_dir/oa1" "$work_dir/oa2" "/oauth2/token"
    replay_recorded_curl \
        "$work_dir/oauth-args" \
        "$work_dir/oauth-stdin" \
        "http://127.0.0.1:$(cat "$work_dir/oa1.port")/oauth2/token"
    echo "hop1 capture ($script): $(cat "$work_dir/oa1" 2>/dev/null || echo '<missing>')"
    echo "hop2 capture ($script): $(cat "$work_dir/oa2" 2>/dev/null || echo '<missing>')"
    if [ -s "$work_dir/oa2" ] && grep -qF 'REGRESSION_SECRET' "$work_dir/oa2"; then
        echo "FAIL: $script oauth POST replayed against a 307 chain (secret reached hop 2: $(cat "$work_dir/oa2"))" >&2
        oauth_failures=$((oauth_failures + 1))
    fi
}

test_shipped_oauth_redirect bash/install/falcon-linux-install.sh function
test_shipped_oauth_redirect bash/install/falcon-linux-uninstall.sh function
test_shipped_oauth_redirect bash/migrate/falcon-linux-migrate.sh function
test_shipped_oauth_redirect \
    bash/containers/falcon-container-sensor-pull/falcon-container-sensor-pull.sh \
    container

record_fetch_tags_curl() {
    local script=$1
    local helper

    helper=$(awk '/^fetch_tags\(\)/,/^}/' "$repo_root/$script")
    [ -n "$helper" ] || fail "fetch_tags not found in $script"

    : >"$work_dir/ft-args"
    : >"$work_dir/ft-stdin"

    (
        curl() {
            printf '%s\n' "$@" >"$work_dir/ft-args"
            cat >"$work_dir/ft-stdin"
            echo '{"token":"mock-registry-token"}'
        }
        curl_command() { echo '{"tags":[]}'; }
        handle_curl_error() { :; }
        json_value() { cat >/dev/null; echo "mock-registry-token"; }
        die() { echo "die: $*" >&2; exit 1; }
        ART_USERNAME="user"
        ART_PASSWORD="REGRESSION_BASIC"
        cs_registry="registry.example.invalid"
        registry_opts="ns"
        repository_name="repo"
        eval "$helper"
        fetch_tags >/dev/null
    )
}

# CAND-002: replay the shipped fetch_tags login curl. Fail if Basic auth or
# the registry password reaches hop 2.
record_fetch_tags_curl \
    bash/containers/falcon-container-sensor-pull/falcon-container-sensor-pull.sh
echo "recorded fetch_tags argv:"
tr '\n' ' ' <"$work_dir/ft-args"
echo
start_redirect_pair "$work_dir/ft1" "$work_dir/ft2" "/v2/token"
replay_recorded_curl \
    "$work_dir/ft-args" \
    "$work_dir/ft-stdin" \
    "http://127.0.0.1:$(cat "$work_dir/ft1.port")/v2/token"
echo "hop2 capture (fetch_tags): $(cat "$work_dir/ft2" 2>/dev/null || echo '<missing>')"
if grep -qF 'REGRESSION_BASIC' "$work_dir/ft2" ||
    grep -qF 'dXNlcjpSRUdSRVNTSU9OX0JBU0lD' "$work_dir/ft2"; then
    fail "fetch_tags registry login forwarded Basic auth to hop 2: $(cat "$work_dir/ft2")"
fi
[ -s "$work_dir/ft2" ] || fail 'fetch_tags replay never reached hop 2'
echo "fetch_tags: hop 2 did not receive REGRESSION_BASIC"

if [ "$oauth_failures" -ne 0 ]; then
    fail "$oauth_failures shipped oauth POST call site(s) leaked REGRESSION_SECRET to hop 2"
fi

echo "PASS: redirect credential leak checks"
