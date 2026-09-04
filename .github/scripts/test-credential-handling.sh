#!/bin/bash

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

echo 'PASS: credential handling regression checks'
