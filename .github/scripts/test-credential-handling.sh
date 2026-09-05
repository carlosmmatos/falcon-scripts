#!/bin/bash

# Credential-handling regressions for the shipped bash helpers.
# curl_command() pins are necessary but not sufficient: get_oauth_token and
# fetch_tags issue their own curl invocations. Those call sites must also
# pass --proto/--proto-redir. The previous harness only extracted
# curl_command(), so it PASSed when oauth proto pins were missing (fail-open).

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# Report an absent or broken search tool as a failure instead of a pass. grep
# returns 0 for a match, 1 for no match, and 2 or more for an error. Only 1 is
# an acceptable result here.
assert_no_match() {
    local description=$1 pattern=$2 tree=$3 include=$4
    local output status

    set +e
    output=$(grep -rnE "$pattern" "$repo_root/$tree" --include="$include")
    status=$?
    set -e

    if [ "$status" -eq 0 ]; then
        echo "$output" >&2
        fail "$description"
    fi
    if [ "$status" -ne 1 ]; then
        fail "grep failed with status $status while checking: $description"
    fi
}

curl() {
    printf '%s\n' "$@" >"$CURL_ARGS_FILE"
    cat >"$CURL_STDIN_FILE"
}

test_curl_helper() {
    local script=$1 token_mode=$2
    local helper mode expected_key

    helper=$(awk '/^curl_command\(\)/,/^}/' "$repo_root/$script")
    [ -n "$helper" ] || fail "curl_command not found in $script"
    eval "$helper"

    # Mode 1 uses the oauth2-bearer configuration key. Mode 0 is the fallback
    # for curl older than 7.33.0 and uses a raw Authorization header. Both must
    # keep the credential on stdin.
    for mode in 1 0; do
        # shellcheck disable=SC2034  # read by the curl_command body under eval
        curl_has_oauth2_bearer=$mode
        if [ "$mode" -eq 1 ]; then
            expected_key='oauth2-bearer = "REGRESSION_SECRET_TOKEN"'
        else
            expected_key='header = "Authorization: Bearer REGRESSION_SECRET_TOKEN"'
        fi

        CURL_ARGS_FILE="$work_dir/args"
        CURL_STDIN_FILE="$work_dir/stdin"
        # shellcheck disable=SC2034  # read by the curl_command body under eval
        proxy=""
        cs_falcon_oauth_token="REGRESSION_SECRET_TOKEN"

        if [ "$token_mode" = "argument" ]; then
            curl_command "$cs_falcon_oauth_token" "https://api.example.invalid/resource"
        else
            curl_command "https://api.example.invalid/resource"
        fi

        if grep -qF "$cs_falcon_oauth_token" "$CURL_ARGS_FILE"; then
            fail "$script exposed the bearer token in curl arguments (mode=$mode)"
        fi
        grep -qF 'https://api.example.invalid/resource' "$CURL_ARGS_FILE" ||
            fail "$script did not pass the expected URL (mode=$mode)"
        grep -qF "$cs_falcon_oauth_token" "$CURL_STDIN_FILE" ||
            fail "$script did not provide the bearer token through stdin (mode=$mode)"
        grep -qF "$expected_key" "$CURL_STDIN_FILE" ||
            fail "$script did not use the expected credential mechanism (mode=$mode)"
        grep -qF -- '--proto' "$CURL_ARGS_FILE" ||
            fail "$script did not restrict the request protocol (mode=$mode)"
        grep -qF -- '--proto-redir' "$CURL_ARGS_FILE" ||
            fail "$script did not restrict the redirect protocol (mode=$mode)"
    done
}

test_curl_helper \
    bash/containers/falcon-container-sensor-pull/falcon-container-sensor-pull.sh argument
test_curl_helper bash/install/falcon-linux-install.sh global
test_curl_helper bash/install/falcon-linux-uninstall.sh global
test_curl_helper bash/migrate/falcon-linux-migrate.sh global

# CAND-010: curl_command() already pins --proto/--proto-redir. The OAuth token
# POST and fetch_tags() registry login are separate curl invocations. The
# previous harness never extracted those call sites, so the suite PASSed when
# their proto pins were missing (fail-open). Deleting oauth proto pins, or
# leaving that equivalent gap, must now fail this script.

assert_proto_pins() {
    local description=$1 args_file=$2
    grep -qF -- '--proto' "$args_file" ||
        fail "$description did not restrict the request protocol (--proto)"
    grep -qF -- '--proto-redir' "$args_file" ||
        fail "$description did not restrict the redirect protocol (--proto-redir)"
}

# Prove the pin assertion itself is fail-closed: an argv without proto pins
# must not be reported as a pass.
{
    printf '%s\n' -X POST -s -L --data '@-' >"$work_dir/unpinned-argv"
    if (assert_proto_pins 'control: unpinned oauth argv' "$work_dir/unpinned-argv") 2>/dev/null; then
        fail 'CAND-010 bar is fail-open: unpinned oauth argv was accepted'
    fi
}

record_oauth_curl_args() {
    local script=$1
    local helper args_file stdin_file

    args_file="$work_dir/oauth-args"
    stdin_file="$work_dir/oauth-stdin"
    : >"$args_file"
    : >"$stdin_file"

    helper=$(awk '/^get_oauth_token\(\)/,/^}/' "$repo_root/$script")
    [ -n "$helper" ] || fail "get_oauth_token not found in $script"

    (
        curl() {
            printf '%s\n' "$@" >"$args_file"
            cat >"$stdin_file"
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

    [ -s "$args_file" ] || fail "$script get_oauth_token never invoked curl"
    grep -qF 'REGRESSION_SECRET' "$stdin_file" ||
        fail "$script get_oauth_token did not send the client secret on curl stdin"
    grep -qF 'oauth2/token' "$args_file" ||
        fail "$script get_oauth_token did not request oauth2/token"
}

record_container_oauth_curl_args() {
    local script=$1
    local block args_file stdin_file

    args_file="$work_dir/oauth-args"
    stdin_file="$work_dir/oauth-stdin"
    : >"$args_file"
    : >"$stdin_file"

    block=$(awk '
        /token_result=\$\(echo "client_id=\$FALCON_CLIENT_ID/ { p = 1 }
        p { print }
        /handle_curl_error \$\?/ { if (p) exit }
    ' "$repo_root/$script")
    [ -n "$block" ] || fail "oauth token curl block not found in $script"

    (
        curl() {
            printf '%s\n' "$@" >"$args_file"
            cat >"$stdin_file"
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

    [ -s "$args_file" ] || fail "$script oauth block never invoked curl"
    grep -qF 'REGRESSION_SECRET' "$stdin_file" ||
        fail "$script oauth block did not send the client secret on curl stdin"
    grep -qF 'oauth2/token' "$args_file" ||
        fail "$script oauth block did not request oauth2/token"
}

pin_failures=0

check_proto_pins() {
    local description=$1 args_file=$2
    if ! grep -qF -- '--proto' "$args_file"; then
        echo "FAIL: $description did not restrict the request protocol (--proto)" >&2
        pin_failures=$((pin_failures + 1))
    fi
    if ! grep -qF -- '--proto-redir' "$args_file"; then
        echo "FAIL: $description did not restrict the redirect protocol (--proto-redir)" >&2
        pin_failures=$((pin_failures + 1))
    fi
}

test_oauth_token_curl_pins() {
    local script=$1
    record_oauth_curl_args "$script"
    check_proto_pins "$script get_oauth_token oauth POST" "$work_dir/oauth-args"
}

test_oauth_token_curl_pins bash/install/falcon-linux-install.sh
test_oauth_token_curl_pins bash/install/falcon-linux-uninstall.sh
test_oauth_token_curl_pins bash/migrate/falcon-linux-migrate.sh
record_container_oauth_curl_args \
    bash/containers/falcon-container-sensor-pull/falcon-container-sensor-pull.sh
check_proto_pins \
    'falcon-container-sensor-pull.sh oauth POST' \
    "$work_dir/oauth-args"

test_fetch_tags_curl_pins() {
    local script=$1
    local helper args_file stdin_file

    helper=$(awk '/^fetch_tags\(\)/,/^}/' "$repo_root/$script")
    [ -n "$helper" ] || fail "fetch_tags not found in $script"

    args_file="$work_dir/fetch-tags-args"
    stdin_file="$work_dir/fetch-tags-stdin"
    : >"$args_file"
    : >"$stdin_file"

    (
        curl() {
            printf '%s\n' "$@" >"$args_file"
            cat >"$stdin_file"
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

    [ -s "$args_file" ] || fail "$script fetch_tags never invoked curl"
    grep -qF 'REGRESSION_BASIC' "$stdin_file" ||
        fail "$script fetch_tags did not pass registry credentials on curl stdin"
    check_proto_pins "$script fetch_tags registry login" "$args_file"
}

test_fetch_tags_curl_pins \
    bash/containers/falcon-container-sensor-pull/falcon-container-sensor-pull.sh

test_xtrace_guard() {
    local script=$1 guard trace_file

    guard=$(awk '/^case \$- in$/,/^esac$/' "$repo_root/$script")
    [ -n "$guard" ] || fail "xtrace guard not found in $script"
    trace_file="$work_dir/xtrace"

    FALCON_CLIENT_SECRET="XTRACE_SECRET_SENTINEL" \
        bash -xc "$guard; : \"\$FALCON_CLIENT_SECRET\"" \
        >/dev/null 2>"$trace_file"

    if grep -qF 'XTRACE_SECRET_SENTINEL' "$trace_file"; then
        fail "$script allowed a credential into bash xtrace output"
    fi
}

test_xtrace_guard bash/containers/falcon-container-sensor-pull/falcon-container-sensor-pull.sh
test_xtrace_guard bash/install/falcon-linux-install.sh
test_xtrace_guard bash/install/falcon-linux-uninstall.sh
test_xtrace_guard bash/migrate/falcon-linux-migrate.sh

test_hash_verification() {
    local script=$1 helper test_file expected_sha

    helper=$(awk '/^verify_sha256\(\)/,/^}/' "$repo_root/$script")
    [ -n "$helper" ] || fail "verify_sha256 not found in $script"
    (
        eval "$helper"
        # verify_sha256 calls die on a mismatch; keep the stub inside the subshell.
        # shellcheck disable=SC2329  # invoked indirectly by verify_sha256
        die() { exit 1; }

        test_file="$work_dir/installer"
        printf '%s' 'verified installer content' >"$test_file"
        expected_sha=$(openssl dgst -sha256 "$test_file" | awk '{ print $NF }')
        verify_sha256 "$test_file" "$expected_sha" ||
            fail "$script rejected a valid installer hash"

        if (verify_sha256 "$test_file" '0000000000000000000000000000000000000000000000000000000000000000'); then
            fail "$script accepted an invalid installer hash"
        fi
        [ ! -e "$test_file" ] || fail "$script retained an installer with an invalid hash"
    )
}

test_hash_verification bash/install/falcon-linux-install.sh
test_hash_verification bash/migrate/falcon-linux-migrate.sh

# The arguments below are grep patterns, not shell expansions.
# shellcheck disable=SC2016
assert_no_match \
    'a Bash error path exposes a credential or raw maintenance-token response' \
    'Invalid Access Token:.*\$cs_falcon_oauth_token|Failed to retrieve maintenance token\. Response:' \
    bash '*.sh'

# shellcheck disable=SC2016
assert_no_match \
    'an EC2 metadata token is exposed in curl arguments' \
    'curl .*X-aws-ec2-metadata-token:.*\$token' \
    bash '*.sh'

# shellcheck disable=SC2016
assert_no_match \
    'an AWS SSM Parameter Store error path prints the decrypted response body' \
    'AWS SSM Parameter Store[^"]*\$response' \
    bash '*.sh'

# shellcheck disable=SC2016
assert_no_match \
    'a PowerShell log statement exposes an authentication or installer token' \
    '(Invoke-FalconAuth|GetToken) - \$content:|Retrieved maintenance token:|Starting .*parameters.*\$(Install|Uninstall)Params' \
    powershell '*.ps1'

if [ "$pin_failures" -ne 0 ]; then
    fail "$pin_failures shipped oauth/fetch_tags curl invocation(s) are missing --proto/--proto-redir"
fi

echo 'PASS: credential handling regression checks'
