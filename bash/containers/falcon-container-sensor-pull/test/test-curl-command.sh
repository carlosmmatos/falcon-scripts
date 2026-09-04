#!/bin/sh
# Regression test for curl_command() argument handling.
#
# curl_command() takes the bearer token as its first parameter and must pass
# only the remaining parameters through to curl. If it does not consume that
# first parameter, curl receives the token as an extra positional parameter and
# treats it as a URL.
#
# This test loads curl_command() from the shipped script, replaces curl with a
# stub that records its argument vector, and checks that the token is never
# handed to curl as an argument. The token always travels on curl's
# configuration input, in both credential mechanisms that the script supports.
#
# Usage: sh test-curl-command.sh [path-to-falcon-container-sensor-pull.sh]

# Re-run under every available shell. The script ships as POSIX sh and runs
# under whatever shell the operator has, so both dash and bash must pass.
if [ -z "${CURL_CMD_TEST_SHELL:-}" ]; then
    overall=0
    for shell_bin in sh dash bash; do
        command -v "$shell_bin" >/dev/null 2>&1 || continue
        echo "=== shell under test: $shell_bin ==="
        CURL_CMD_TEST_SHELL="$shell_bin" "$shell_bin" "$0" "$@" || overall=1
        echo
    done
    exit "$overall"
fi

TEST_DIR=$(dirname "$0")
SCRIPT="${1:-$TEST_DIR/../falcon-container-sensor-pull.sh}"

if [ ! -f "$SCRIPT" ]; then
    echo "FATAL: cannot find script under test: $SCRIPT" >&2
    exit 1
fi

TMPDIR_TEST=$(mktemp -d)
ARGV_FILE="$TMPDIR_TEST/argv"
STDIN_FILE="$TMPDIR_TEST/stdin"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

PASS=0
FAIL=0

pass() {
    PASS=$((PASS + 1))
    echo "  ok    - $1"
}

fail() {
    FAIL=$((FAIL + 1))
    echo "  NOT OK - $1"
}

# A token shaped like the tokens the script really handles: dot-separated
# base64url segments. Every segment is short enough to be a valid DNS label,
# which is what makes an accidental positional argument reach the resolver.
TOKEN="eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmYy1kZWFkYmVlZiJ9.c2lnbmF0dXJl"
URL="https://example.com/v2/tags/list"

# Load the real curl_command() from the shipped script so the test tracks the
# code that ships, not a copy of it.
curl_command_source=$(sed -n '/^curl_command() {$/,/^}$/p' "$SCRIPT")
if [ -z "$curl_command_source" ]; then
    echo "FATAL: could not extract curl_command() from $SCRIPT" >&2
    exit 1
fi
eval "$curl_command_source"

# Stub curl. Records each argument on its own line, and records stdin when the
# caller asks curl to read a header from it.
curl() {
    : >"$ARGV_FILE"
    : >"$STDIN_FILE"
    for arg in "$@"; do
        printf '%s\n' "$arg" >>"$ARGV_FILE"
        if [ "$arg" = "-K-" ]; then
            read_stdin=yes
        fi
    done
    if [ "${read_stdin:-no}" = "yes" ]; then
        cat >"$STDIN_FILE"
    fi
    read_stdin=no
}

# The token must never be handed to curl in any argument.
assert_token_not_in_arguments() {
    found=no
    while IFS= read -r arg; do
        case "$arg" in
            *"$TOKEN"*) found=yes ;;
        esac
    done <"$ARGV_FILE"

    if [ "$found" = "yes" ]; then
        fail "$1: token reached curl arguments"
        echo "        argv: $(tr '\n' ' ' <"$ARGV_FILE")"
    else
        pass "$1: token is absent from curl arguments"
    fi
}

assert_file_contains() {
    # Use -- so that a pattern starting with a dash is not read as an option.
    if grep -qF -- "$2" "$3"; then
        pass "$1"
    else
        fail "$1"
        echo "        contents: $(tr '\n' ' ' <"$3")"
    fi
}

assert_url_passed_through() {
    assert_file_contains "$1: request URL reached curl" "$URL" "$ARGV_FILE"
}

# curl_command() picks its credential mechanism from curl_has_oauth2_bearer.
# Mode 1 uses the oauth2-bearer configuration key, which curl 7.33.0 added.
# Mode 0 is the fallback for older curl and sends a raw Authorization header.
# Both must keep the token on stdin and off the argument vector.
for mode in 1 0; do
    # shellcheck disable=SC2034  # read by the curl_command body loaded with eval
    curl_has_oauth2_bearer=$mode
    if [ "$mode" -eq 1 ]; then
        label="oauth2-bearer config"
        expected="oauth2-bearer = \"$TOKEN\""
    else
        label="raw header fallback"
        expected="header = \"Authorization: Bearer $TOKEN\""
    fi

    echo "case: $label (curl_has_oauth2_bearer=$mode)"
    curl_command "$TOKEN" "$URL"
    assert_token_not_in_arguments "$label"
    assert_url_passed_through "$label"
    assert_file_contains "$label: token delivered over stdin" \
        "$expected" "$STDIN_FILE"
    assert_file_contains "$label: curl reads the configuration from stdin" \
        "-K-" "$ARGV_FILE"
    assert_file_contains "$label: request protocol restricted" \
        "--proto" "$ARGV_FILE"
    assert_file_contains "$label: redirect protocol restricted" \
        "--proto-redir" "$ARGV_FILE"
    echo
done

echo "passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ]
