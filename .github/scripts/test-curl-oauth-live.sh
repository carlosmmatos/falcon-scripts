#!/bin/sh

# Confirms how the installed curl handles an OAuth 2 bearer credential that
# arrives on its configuration input. The script adapts to the curl it finds,
# so it runs on RHEL/CentOS 7 (curl 7.29.0, python2) with no extra packages.

set -eu

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
for candidate in python3 python2 python; do
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
except ImportError:  # Python 2, which is all that RHEL/CentOS 7 provides.
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

output_path = sys.argv[1]
port = int(sys.argv[2])
redirect_to = sys.argv[3] if len(sys.argv) > 3 else ""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # The marker shows that a request arrived. Without it, an empty capture
        # file cannot show the difference between a credential that curl
        # removed and a connection that never happened.
        with open(output_path, "w") as handle:
            handle.write("REQUEST_ARRIVED|auth=[%s]"
                         % self.headers.get("Authorization", ""))
        if redirect_to:
            self.send_response(302)
            self.send_header("Location", redirect_to)
        else:
            self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


HTTPServer.allow_reuse_address = True
# Bind every interface. curl can resolve "localhost" to ::1, and a server bound
# only to 127.0.0.1 refuses that connection and gives a false failure.
server = HTTPServer(("0.0.0.0", port), Handler)

with open(output_path + ".ready", "w") as handle:
    handle.write("ready")

# Serve one request, then stop. The timeout makes sure the process always ends.
server.timeout = 20
server.handle_request()
PY

start_server() {
    output=$1
    port=$2
    redirect_to=${3:-}

    rm -f "$output" "$output.ready"
    "$python_bin" "$server_script" "$output" "$port" "$redirect_to" &
    server_pids="$server_pids $!"
}

wait_for_server() {
    output=$1
    attempt=0

    while [ "$attempt" -lt 15 ]; do
        if [ -f "$output.ready" ]; then
            return 0
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    fail "the capture server for $output did not start"
}

assert_marker() {
    file=$1
    expected=$2
    description=$3
    actual=""

    [ -s "$file" ] || fail "$description (no request reached the capture server)"
    actual=$(cat "$file")
    [ "$actual" = "$expected" ] ||
        fail "$description (expected '$expected', received '$actual')"
}

auth_config_for() {
    case $1 in
        oauth2-bearer) printf 'oauth2-bearer = "%s"\n' "$token" ;;
        header) printf 'header = "Authorization: Bearer %s"\n' "$token" ;;
        *) fail "unknown credential mechanism: $1" ;;
    esac
}

token=CONTAINER_LIVE_TEST_TOKEN
curl --version | head -n 1

# curl 7.33.0 added the oauth2-bearer option. Compare the version with awk
# because busybox sort has no -V option.
if curl --version | head -n 1 |
    awk '{ split($2, v, "."); exit !(v[1] > 7 || (v[1] == 7 && v[2] >= 33)) }'; then
    active_mode=oauth2-bearer
else
    active_mode=header
fi
echo "Credential mechanism under test: $active_mode"

# 1. The mechanism this curl uses must deliver the credential to the same host.
start_server "$work_dir/direct" 28768
wait_for_server "$work_dir/direct"
auth_config_for "$active_mode" |
    curl --silent --show-error -K- --url http://127.0.0.1:28768/test
assert_marker "$work_dir/direct" "REQUEST_ARRIVED|auth=[Bearer $token]" \
    "the $active_mode mechanism did not transmit the credential"

# 2. curl must remove the credential when a redirect crosses to another host.
start_server "$work_dir/redirect" 28769 'http://localhost:28770/target'
start_server "$work_dir/target" 28770
wait_for_server "$work_dir/redirect"
wait_for_server "$work_dir/target"
auth_config_for "$active_mode" |
    curl --silent --show-error -L -K- --url http://127.0.0.1:28769/start
assert_marker "$work_dir/redirect" "REQUEST_ARRIVED|auth=[Bearer $token]" \
    'the first request of the redirect chain did not carry the credential'
assert_marker "$work_dir/target" 'REQUEST_ARRIVED|auth=[]' \
    "the $active_mode credential crossed a redirect to another host"

# 3. On a modern curl, also confirm that the older fallback still works. This
#    keeps the fallback path tested on the machines that do not need it.
if [ "$active_mode" = "oauth2-bearer" ]; then
    start_server "$work_dir/fallback" 28771
    wait_for_server "$work_dir/fallback"
    auth_config_for header |
        curl --silent --show-error -K- --url http://127.0.0.1:28771/test
    assert_marker "$work_dir/fallback" "REQUEST_ARRIVED|auth=[Bearer $token]" \
        'the raw-header fallback did not transmit the credential'
fi

# 4. A stray bare argument must not become a request. This is the guard that
#    stops a leaked credential from reaching a name server.
if auth_config_for "$active_mode" |
    curl --silent --show-error --proto '=https' --proto-redir '=https' -K- \
        "$token" >/dev/null 2>"$work_dir/proto-error"; then
    fail 'the protocol guard accepted a bare argument as a request'
fi
echo "Protocol guard rejected a bare argument: $(cat "$work_dir/proto-error")"

echo "PASS: curl credential handling ($active_mode mode)"
