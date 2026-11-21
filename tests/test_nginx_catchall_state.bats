#!/usr/bin/env bats
# Tests for _nginx_catchall_coverage_from_text. Finding `default_server` and
# `return 444` anywhere in the merged config is not enough: the state must be
# per-port and scoped to one server block, or a 443-only vhost reads as covered.

load helpers.bash

setup() {
    _vpssec_load
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/nginx.sh"
}

# The <have> half of the "<needed> <have>" answer.
_have() {
    local coverage
    coverage=$(_nginx_catchall_coverage_from_text "$1") || return
    printf '%s\n' "${coverage#* }"
}

@test "catchall: both 80 and 443 in one server block → both" {
    local cfg='server {
    listen 80 default_server;
    listen 443 ssl default_server;
    server_name _;
    return 444;
}'
    run _have "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "both" ]
}

@test "catchall: 80 and 443 in separate blocks → both" {
    local cfg='server {
    listen 80 default_server;
    server_name _;
    return 444;
}

server {
    listen 443 ssl default_server;
    server_name _;
    return 444;
}'
    run _have "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "both" ]
}

@test "catchall: only port 80 has catchall, 443 vhost present (regression)" {
    # 80 has a catchall but 443 has a real cert vhost without one. Seeing
    # default_server somewhere AND return 444 somewhere must not read as passed.
    local cfg='server {
    listen 80 default_server;
    server_name _;
    return 444;
}

server {
    listen 443 ssl;
    server_name app.example.com;
    ssl_certificate /etc/ssl/cert.pem;
    return 200 "ok";
}'
    run _have "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "80only" ]
}

@test "catchall: only port 443 has catchall" {
    local cfg='server {
    listen 443 ssl default_server;
    server_name _;
    return 444;
}

server {
    listen 80;
    server_name app.example.com;
    return 200 "ok";
}'
    run _have "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "443only" ]
}

@test "catchall: neither port has catchall" {
    local cfg='server {
    listen 80;
    server_name app.example.com;
    return 200 "ok";
}'
    run _have "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "catchall: empty config → none" {
    run _have ""
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "catchall: IPv6-bracket form [::]:80 default_server detected" {
    local cfg='server {
    listen [::]:80 default_server;
    listen [::]:443 ssl default_server;
    return 444;
}'
    run _have "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "both" ]
}

@test "catchall: 0.0.0.0:80 default_server detected" {
    local cfg='server {
    listen 0.0.0.0:80 default_server;
    listen 0.0.0.0:443 ssl default_server;
    return 444;
}'
    run _have "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "both" ]
}

@test "catchall: port 8080 must NOT match port 80" {
    # Defensive against a substring-match bug. listen 8080 default_server
    # with return 444 should NOT count as a port-80 catchall.
    local cfg='server {
    listen 8080 default_server;
    server_name _;
    return 444;
}'
    run _have "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "catchall: port 4430 must NOT match port 443" {
    local cfg='server {
    listen 4430 default_server;
    server_name _;
    return 444;
}'
    run _have "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "catchall: return 444 in ONE block does not propagate to another" {
    # Cross-block scope check: 80 has default_server but no return 444; on 443
    # the 444 is in the second server, not the default. Should not aggregate.
    local cfg='server {
    listen 80 default_server;
    server_name _;
    root /var/www/html;
}

server {
    listen 443 ssl;
    server_name www.example.com;
    root /var/www/html;
}

server {
    listen 443;
    server_name app.example.com;
    return 444;
}'
    run _have "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "catchall: commented-out catchall is ignored" {
    local cfg='server {
    listen 80 default_server;
    server_name _;
    # return 444;
    return 200 "still alive";
}'
    run _have "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "none" ]
}

@test "catchall: location blocks inside server don't break brace tracking" {
    local cfg='server {
    listen 80 default_server;
    listen 443 ssl default_server;
    server_name _;
    location / {
        deny all;
    }
    location /healthz {
        return 200 "ok";
    }
    return 444;
}'
    run _have "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "both" ]
}

@test "catchall: one-liner server block handled" {
    local cfg='server { listen 80 default_server; return 444; }'
    run _have "$cfg"
    [ "$status" -eq 0 ]
    [ "$output" = "80only" ]
}

@test "catchall: a server returning 444 that is not its port's default is no catchall" {
    run _have 'server { listen 80; server_name www.example; root /srv; }
server { listen 80; server_name x.example; return 444; }'
    [ "$output" = "none" ]
    run _have 'server { listen 80; server_name x.example; return 444; }
server { listen 80 default_server; server_name www.example; root /srv; }'
    [ "$output" = "none" ]
}

@test "catchall: with no default_server the first server on the port is its default" {
    run _have 'server { listen 80; server_name x.example; return 444; }
server { listen 80; server_name www.example; root /srv; }'
    [ "$output" = "80only" ]
    run _have 'server { listen 80 default_server; return 444; }
server { listen 443 ssl; server_name x.example; return 444; }
server { listen 443 ssl; server_name www.example; root /srv; }'
    [ "$output" = "both" ]
}

@test "catchall: a 444 in a location, beside locations that serve, is no catchall" {
    # Unknown hosts asking for anything but /.git reach the application.
    run _have 'http { server { listen 80 default_server;
    location /.git { return 444; }
    location / { proxy_pass http://127.0.0.1:3000; } } }'
    [ "$output" = "none" ]
    run _have 'http { server { listen 80 default_server;
    location / { return 444; location /x { return 444; } } } }'
    [ "$output" = "80only" ]
    run _have 'http { server { listen 80 default_server;
    location / { return 444; }
    location /app { proxy_pass http://127.0.0.1:3000; } } }'
    [ "$output" = "none" ]
}

@test "catchall: a location nested or exact on / is not the whole server" {
    run _have 'http { server { listen 80 default_server; location = / { return 444; } } }'
    [ "$output" = "none" ]
    run _have 'http { server { listen 80 default_server; location / { location /a { return 444; } } } }'
    [ "$output" = "none" ]
}

@test "catchall: Proxy-agent's port 80, one server answering 444 to any other Host, is covered" {
    run _nginx_catchall_coverage_from_text 'http { server {
    listen 80; listen [::]:80;
    server_name example.com;
    server_tokens off;
    if ($http_host !~* "^example\.com(:80)?$") {
        return 444;
    }
    return 301 https://example.com:8443$request_uri;
} }'
    [ "$output" = "80 80only" ]
}

@test "catchall: an if that does not refuse other hosts is no catchall" {
    run _have 'http { server { listen 80;
    if ($request_method = POST) { return 444; }
    root /srv; } }'
    [ "$output" = "none" ]
    run _have 'http { server { listen 80;
    if ($host = bad.example) { return 444; }
    root /srv; } }'
    [ "$output" = "none" ]
    run _have 'http { server { listen 80;
    if ($host != example.com) { return 301 https://example.com; }
    if ($request_method = POST) { return 444; }
    root /srv; } }'
    [ "$output" = "none" ]
}

@test "catchall: \$host matched negatively either way counts" {
    run _have 'http { server { listen 80; if ($host != example.com) { return 444; } } }'
    [ "$output" = "80only" ]
    run _have 'http { server { listen 80; if ($host !~ ^(a|b)\.example$) { return 444; } } }'
    [ "$output" = "80only" ]
}

@test "coverage: ssl_reject_handshake counts as the 443 catchall" {
    run _have 'server { listen 80 default_server; return 444; }
server { listen 443 ssl default_server; ssl_reject_handshake on; }'
    [ "$output" = "both" ]
}

@test "coverage: 443 is owed only when nginx serves it" {
    run _nginx_catchall_coverage_from_text 'http { server { listen 80; } server { listen 80 default_server; return 444; } }'
    [ "$output" = "80 80only" ]
    _nginx_catchall_covered "$output"

    run _nginx_catchall_coverage_from_text 'http { server { listen 443 ssl; } server { listen 80 default_server; return 444; } }'
    [ "$output" = "both 80only" ]
    _vpssec_refute _nginx_catchall_covered "$output"
}

@test "coverage: a 443 catchall alone does not make nginx serve 443" {
    run _nginx_catchall_coverage_from_text 'http { server { listen 80; }
server { listen 80 default_server; listen 443 ssl default_server; return 444; } }'
    [ "$output" = "80 both" ]
}

@test "coverage: a stream server on 443 is not nginx serving HTTPS" {
    run _nginx_catchall_coverage_from_text 'stream { server { listen 443 ssl; } }
http { server { listen 80 default_server; return 444; } }'
    [ "$output" = "80 80only" ]
}

# ---- rivals: default servers the fix's own default_server would duplicate --------

@test "rivals: Debian's stock default site is one, named by its server_name" {
    run _nginx_catchall_coverage_from_text 'http { server {
    listen 80 default_server;
    listen [::]:80 default_server;
    root /var/www/html;
    server_name _;
} }' rivals
    [ "$output" = $'80\t_' ]
}

@test "rivals: a catchall is not one, on either port" {
    run _nginx_catchall_coverage_from_text 'server { listen 80 default_server; return 444; }
server { listen 443 ssl default_server; ssl_reject_handshake on; }' rivals
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "rivals: a 443 default_server that answers is one, a plain vhost is not" {
    run _nginx_catchall_coverage_from_text 'http { server { listen 80; server_name a.test; }
server { listen 443 ssl default_server; server_name b.test; } }' rivals
    [ "$output" = $'443\tb.test' ]
}

@test "missing ports: only what the coverage still lacks" {
    [ "$(_nginx_catchall_missing_ports 'both none')" = "80 443" ]
    [ "$(_nginx_catchall_missing_ports 'both 80only')" = "443" ]
    [ "$(_nginx_catchall_missing_ports 'both 443only')" = "80" ]
    [ "$(_nginx_catchall_missing_ports '80 none')" = "80" ]
    [ "$(_nginx_catchall_missing_ports '80 443only')" = "80" ]
}
