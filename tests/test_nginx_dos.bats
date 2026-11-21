#!/usr/bin/env bats
# The nginx DoS timeouts: the largest value a directive takes anywhere is the
# finding, named by where it is set, since an http{} value overrides no server
# or location that sets its own. nginx's default counts where nothing sets one.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/nginx.sh"
}

# NGINX_DUMP as `nginx -T` prints one main file holding $1.
_config() {
    NGINX_DUMP="# configuration file /etc/nginx/nginx.conf:
$1"
}

# The id and desc of what the audit emitted for directive $1.
_finding() {
    _nginx_audit_dos_hardening >/dev/null
    jq -r --arg id "nginx.${1}_high" '.[] | select(.id == $id) | .desc' "$VPSSEC_STATE/checks.json"
}

# Every other DoS directive at its hardened value, so only the one under test differs.
_hardened() {
    printf 'client_header_timeout 10s; client_body_timeout 10s; send_timeout 10s;
keepalive_timeout 30s; reset_timedout_connection on; limit_req_zone $binary_remote_addr zone=a:1m rate=1r/s;'
}

@test "dos: a server's own value is judged though http{} sets a lower one after it" {
    # The old reader took the last value in the file: this config passed.
    _config "http { server { listen 80; server_name a.example; client_body_timeout 120s; }
    $(_hardened) }"
    [ "$(_finding client_body_timeout)" = "client_body_timeout=120s in server a.example (CIS 5.2.1: ≤10s)" ]
}

@test "dos: a gRPC location's long timeout is named with its location, not exempt" {
    # Proxy-agent's fallback location on both proxy hosts.
    _config "http { $(_hardened)
    server { listen 127.0.0.1:31302 http2; server_name example.com;
        location /grpc/ { client_body_timeout 5m; grpc_pass grpc://127.0.0.1:31307; } } }"
    [ "$(_finding client_body_timeout)" = "client_body_timeout=5m in server example.com, location /grpc/ (CIS 5.2.1: ≤10s)" ]
}

@test "dos: the largest of several values is the one reported" {
    _config "http { $(_hardened) send_timeout 20s;
    server { listen 80; server_name a.example; send_timeout 2m; }
    server { listen 81; server_name b.example; send_timeout 30s; } }"
    [[ "$(_finding send_timeout)" == "send_timeout=2m in server a.example "* ]]
}

@test "dos: nginx's default counts where a server sets none and http{} sets none" {
    _config "http { client_header_timeout 10s; send_timeout 10s; keepalive_timeout 30s;
    server { listen 80; server_name a.example; client_body_timeout 5s; }
    server { listen 81; server_name b.example; } }"
    [ "$(_finding client_body_timeout)" = "client_body_timeout=60s in server b.example (nginx default: not set there) (CIS 5.2.1: ≤10s)" ]
}

@test "dos: the default does not count once every server sets its own" {
    _config "http { client_header_timeout 10s; send_timeout 10s; keepalive_timeout 30s;
    server { listen 80; server_name a.example; client_body_timeout 5s; }
    server { listen 81; server_name b.example; client_body_timeout 8s; } }"
    [ -z "$(_finding client_body_timeout)" ]
}

@test "dos: nothing set anywhere is nginx's default" {
    _config 'http { }'
    [ "$(_finding client_header_timeout)" = "client_header_timeout=60s in http{} (nginx default: not set there) (CIS 5.2.1: ≤10s; nginx default 60s leaves Slowloris vulnerable)" ]
}

@test "dos: a server named _ is named by its listen address" {
    _config "http { $(_hardened) server { listen 8080 default_server; server_name _; keepalive_timeout 65 60; } }"
    [ "$(_finding keepalive_timeout)" = "keepalive_timeout=65 60 in server 8080 (recommended: ≤30s; nginx default 75s)" ]
}

@test "dos: every directive within its threshold passes" {
    _config "http { $(_hardened) server { listen 80; server_name a.example; } }"
    _nginx_audit_dos_hardening >/dev/null
    [ "$(jq -r '[.[].id] | join(",")' "$VPSSEC_STATE/checks.json")" = "nginx.dos_hardening_ok" ]
}
