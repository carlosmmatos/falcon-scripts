#!/bin/bash

# Live two-port 307 capture for the shipped OAuth POST and fetch_tags login
# curls. High fail (CAND-001) is only (B): the body secret on hop 2.
# CAND-002 logs (A) hop-2 contact vs (B) Basic/credential on hop 2; only (B)
# fails this script as a credential leak. The mock is fail-closed: an unpinned
# control POST must leak, or later "no leak" results are meaningless.
#
# OAuth POSTs must also omit -L/--location: curl replays the credential body on
# a 307/308 follow, and an https→https redirect defeats --proto-redir '=https'.
# Hop 2 missing is a PASS for CAND-001 (expected when follow is disabled).

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

server_script="$repo_root/.github/scripts/redirect-capture-server.py"
[ -f "$server_script" ] || fail "missing $server_script"

tls_cert=""
tls_key=""
if command -v openssl >/dev/null 2>&1; then
    openssl req -x509 -newkey rsa:2048 -keyout "$work_dir/key.pem" -out "$work_dir/cert.pem" \
        -days 1 -nodes -subj '/CN=127.0.0.1' >/dev/null 2>&1
    tls_cert="$work_dir/cert.pem"
    tls_key="$work_dir/key.pem"
fi

start_server() {
    output=$1
    redirect_to=${2:-}
    use_tls=${3:-}

    rm -f "$output" "$output.ready" "$output.port"
    if [ -n "$use_tls" ]; then
        [ -n "$tls_cert" ] || fail 'HTTPS capture requested but openssl/cert is unavailable'
        [ -n "$redirect_to" ] || redirect_to='-'
        "$python_bin" "$server_script" "$output" "$redirect_to" "$tls_cert" "$tls_key" &
    else
        [ -n "$redirect_to" ] || redirect_to='-'
        "$python_bin" "$server_script" "$output" "$redirect_to" &
    fi
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
    scheme=${4:-http}

    use_tls=""
    [ "$scheme" = https ] && use_tls=yes
    start_server "$hop2" "" "$use_tls"
    wait_for_server "$hop2"
    hop2_port=$(cat "$hop2.port")
    start_server "$hop1" "${scheme}://127.0.0.1:${hop2_port}${hop2_path}" "$use_tls"
    wait_for_server "$hop1"
    hop1_port=$(cat "$hop1.port")
}

# (A) hop 2 was contacted. (B) the named credential string is in the hop 2
# capture. Only (B) is a High credential leak.
report_ab() {
    local cand=$1 hop2=$2 pattern=$3
    if [ -s "$hop2" ]; then
        echo "$cand (A) hop2_contacted=yes capture=$(cat "$hop2")"
    else
        echo "$cand (A) hop2_contacted=no"
    fi
    if [ -s "$hop2" ] && grep -qE -- "$pattern" "$hop2"; then
        echo "$cand (B) credential_on_hop2=yes"
        return 0
    fi
    echo "$cand (B) credential_on_hop2=no"
    return 1
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

    case $url in
        https://*)
            replay_args=(--insecure "${replay_args[@]}")
            ;;
    esac

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

# Standalone -L/--location on the shipped oauth POST argv would follow a
# 307/308 and replay the client secret. Reject those flags before the live
# replay so reintroducing follow fails closed even if hop-2 capture softens.
assert_oauth_post_no_follow() {
    local script=$1
    local arg

    while IFS= read -r arg; do
        case $arg in
            -L | --location | --location-trusted)
                echo "FAIL: $script oauth POST still follows redirects ($arg)" >&2
                return 1
                ;;
        esac
    done <"$work_dir/oauth-args"
    return 0
}

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

    if ! assert_oauth_post_no_follow "$script"; then
        oauth_failures=$((oauth_failures + 1))
    fi

    start_redirect_pair "$work_dir/oa1" "$work_dir/oa2" "/oauth2/token" https
    replay_recorded_curl \
        "$work_dir/oauth-args" \
        "$work_dir/oauth-stdin" \
        "https://127.0.0.1:$(cat "$work_dir/oa1.port")/oauth2/token"
    echo "hop1 capture ($script): $(cat "$work_dir/oa1" 2>/dev/null || echo '<missing>')"
    echo "hop2 capture ($script): $(cat "$work_dir/oa2" 2>/dev/null || echo '<missing>')"

    # Harness integrity: the recorded request must actually hit hop 1 with the
    # secret, or a later hop-2-empty PASS would be meaningless (fail-open).
    if ! [ -s "$work_dir/oa1" ] || ! grep -qF 'REGRESSION_SECRET' "$work_dir/oa1"; then
        echo "FAIL: $script oauth POST never delivered REGRESSION_SECRET to hop 1" >&2
        oauth_failures=$((oauth_failures + 1))
    fi

    if report_ab "CAND-001 $script" "$work_dir/oa2" 'REGRESSION_SECRET'; then
        echo "FAIL: $script oauth POST HTTPS→HTTPS 307 (B) body secret on hop 2" >&2
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

# CAND-002: replay the shipped fetch_tags login curl over HTTPS→HTTPS.
# (A) hop 2 contacted is a proto-pin / follow gap (Medium at most).
# (B) Basic auth or the password on hop 2 is the only High leak.
record_fetch_tags_curl \
    bash/containers/falcon-container-sensor-pull/falcon-container-sensor-pull.sh
echo "recorded fetch_tags argv:"
tr '\n' ' ' <"$work_dir/ft-args"
echo
start_redirect_pair "$work_dir/ft1" "$work_dir/ft2" "/v2/token" https
replay_recorded_curl \
    "$work_dir/ft-args" \
    "$work_dir/ft-stdin" \
    "https://127.0.0.1:$(cat "$work_dir/ft1.port")/v2/token"
echo "hop1 capture (fetch_tags): $(cat "$work_dir/ft1" 2>/dev/null || echo '<missing>')"
echo "hop2 capture (fetch_tags): $(cat "$work_dir/ft2" 2>/dev/null || echo '<missing>')"
[ -s "$work_dir/ft2" ] || fail 'CAND-002 inconclusive: hop 2 was not contacted (cannot assert (B))'
if report_ab 'CAND-002 fetch_tags' "$work_dir/ft2" \
    'REGRESSION_BASIC|dXNlcjpSRUdSRVNTSU9OX0JBU0lD|auth=\[Basic'; then
    fail "CAND-002 (B): fetch_tags forwarded Basic auth to hop 2: $(cat "$work_dir/ft2")"
fi

if [ "$oauth_failures" -ne 0 ]; then
    fail "$oauth_failures shipped oauth POST call site(s) leaked REGRESSION_SECRET to hop 2"
fi

echo "PASS: redirect credential leak checks"
