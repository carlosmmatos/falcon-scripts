#!/bin/bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

curl() {
    printf '%s\n' "$@" >"$CURL_ARGS_FILE"
    cat >"$CURL_STDIN_FILE"
}

export CURL_ARGS_FILE CURL_STDIN_FILE

test_curl_helper() {
    local script=$1 token_mode=$2
    local helper

    helper=$(awk '/^curl_command\(\)/,/^}/' "$repo_root/$script")
    [ -n "$helper" ] || fail "curl_command not found in $script"
    eval "$helper"

    for old_curl in 0 1; do
        CURL_ARGS_FILE="$work_dir/args"
        CURL_STDIN_FILE="$work_dir/stdin"
        proxy=""
        export proxy
        cs_falcon_oauth_token="REGRESSION_SECRET_TOKEN"

        if [ "$token_mode" = "argument" ]; then
            curl_command "$cs_falcon_oauth_token" "https://api.example.invalid/resource"
        else
            curl_command "https://api.example.invalid/resource"
        fi

        if grep -qF "$cs_falcon_oauth_token" "$CURL_ARGS_FILE"; then
            fail "$script exposed the bearer token in curl arguments (old_curl=$old_curl)"
        fi
        grep -qF 'https://api.example.invalid/resource' "$CURL_ARGS_FILE" ||
            fail "$script did not pass the expected URL (old_curl=$old_curl)"
        grep -qF "$cs_falcon_oauth_token" "$CURL_STDIN_FILE" ||
            fail "$script did not provide the bearer token through stdin (old_curl=$old_curl)"
        grep -qF -- '--proto' "$CURL_ARGS_FILE" ||
            fail "$script did not restrict the request protocol (old_curl=$old_curl)"
        grep -qF -- '--proto-redir' "$CURL_ARGS_FILE" ||
            fail "$script did not restrict the redirect protocol (old_curl=$old_curl)"
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
    eval "$helper"
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
}

test_hash_verification bash/install/falcon-linux-install.sh
test_hash_verification bash/migrate/falcon-linux-migrate.sh

if rg -n 'Invalid Access Token:.*\$cs_falcon_oauth_token|Failed to retrieve maintenance token\. Response:' \
    "$repo_root/bash" --glob '*.sh'; then
    fail 'a Bash error path exposes a credential or raw maintenance-token response'
fi

if rg -n 'curl .*X-aws-ec2-metadata-token:.*\$token' \
    "$repo_root/bash" --glob '*.sh'; then
    fail 'an EC2 metadata token is exposed in curl arguments'
fi

if rg -n '(Invoke-FalconAuth|GetToken) - \$content:|Retrieved maintenance token:|Starting .*parameters.*\$(Install|Uninstall)Params' \
    "$repo_root/powershell" --glob '*.ps1'; then
    fail 'a PowerShell log statement exposes an authentication or installer token'
fi

echo 'PASS: credential handling regression checks'
