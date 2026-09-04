#!/bin/sh

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

start_capture_server() {
    port=$1 output=$2
    python3 -c 'import http.server, socketserver, sys
socketserver.TCPServer.allow_reuse_address = True
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open(sys.argv[1], "w") as output:
            output.write(self.headers.get("Authorization", ""))
        self.send_response(204)
        self.end_headers()
    def log_message(self, *args):
        pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[2])), Handler).handle_request()
' "$output" "$port" &
    last_server_pid=$!
    server_pids="$server_pids $last_server_pid"
}

token=CONTAINER_LIVE_TEST_TOKEN
curl --version | head -n 1

start_capture_server 28768 "$work_dir/header"
header_pid=$last_server_pid
sleep 1
printf 'oauth2-bearer = "%s"\n' "$token" |
    curl --silent --show-error -K- --url http://127.0.0.1:28768/test
wait "$header_pid"
[ "$(cat "$work_dir/header")" = "Bearer $token" ] || {
    echo 'FAIL: OAuth configuration did not transmit the expected header' >&2
    exit 1
}

start_capture_server 28770 "$work_dir/redirect-header"
target_pid=$last_server_pid
python3 -c 'import http.server, socketserver
socketserver.TCPServer.allow_reuse_address = True
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://localhost:28770/target")
        self.end_headers()
    def log_message(self, *args):
        pass
http.server.HTTPServer(("127.0.0.1", 28769), Handler).handle_request()
' &
redirect_pid=$!
server_pids="$server_pids $redirect_pid"
sleep 1
printf 'oauth2-bearer = "%s"\n' "$token" |
    curl --silent --show-error -L -K- --url http://127.0.0.1:28769/start
wait "$redirect_pid" "$target_pid"
[ ! -s "$work_dir/redirect-header" ] || {
    echo 'FAIL: OAuth credential followed a cross-host redirect' >&2
    exit 1
}

echo 'PASS: OAuth stdin configuration and cross-host redirect protection'
