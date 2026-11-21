#!/usr/bin/env bats
# The nginx2root note: an nginx upstream-older than 1.31.9 / 1.30.7, configured
# with a feature one of the five flaws needs. Unscored, since a distribution may
# have backported the fixes under the old version number.

load helpers.bash

setup() {
    _vpssec_load core/distro.sh core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/webapp.sh"
    VPSSEC_PKG_MGR=apt
    file_package_verified() { echo nginx; }
    _nginx_reports 1.31.8
}

# An nginx whose -v reports version $1, on stderr as nginx prints it.
_nginx_reports() {
    _vpssec_stub_script nginx <<SH
[[ "\$1" == -v ]] && echo "nginx version: nginx/$1" >&2
exit 0
SH
}

# NGINX_DUMP as `nginx -T` prints one main file holding the http{} body given.
_config() {
    NGINX_DUMP="# configuration file /etc/nginx/nginx.conf:
events { worker_connections 1024; }
$1"
}

# The lab host before its 11-18 upgrade: Proxy-agent's gRPC fallback over HTTP/2.
_proxy_agent_config() {
    _config 'http {
    server {
        listen 127.0.0.1:31302 so_keepalive=on proxy_protocol;http2 on;
        server_name example.com;
        location /grpc/ { grpc_pass grpc://127.0.0.1:31307; }
    }
    server { listen 80; server_name example.com; return 301 https://example.com$request_uri; }
}'
}

_note() {
    jq -r '.[] | select(.id == "webapp.nginx2root") | "\(.severity) \(.status)|\(.desc)|\(.suggestion)"' "$STATE_CHECKS_FILE"
}

@test "versions: before each maintained branch's fix, and every older branch, are affected" {
    local v wrong=""
    for v in 1.31.8 1.31.0 1.30.6 1.30.0 1.29.8 1.28.3 1.26.3 1.24.0 0.8.55; do
        _webapp_nginx2root_affected "$v" || wrong+="[$v not affected] "
    done
    for v in 1.31.9 1.31.10 1.30.7 1.30.12 1.32.0 1.33.1 2.0.1; do
        _webapp_nginx2root_affected "$v" && wrong+="[$v affected] "
    done
    # OpenResty numbers its own releases: 1.27.1.2 is not nginx 1.27.1.
    _webapp_nginx2root_affected 1.27.1.2 && wrong+="[openresty affected] "
    [ -z "$wrong" ] || { echo "$wrong"; return 1; }
}

@test "the version is nginx's own, not a fork's" {
    run _webapp_nginx_version
    [ "$output" = "1.31.8" ]
    _vpssec_stub_script nginx <<<'echo "nginx version: openresty/1.27.1.2" >&2'
    run _webapp_nginx_version
    [ -z "$output" ]
}

@test "the lab host before its upgrade: HTTP/2 with a backend, two CVEs, how to confirm a backport" {
    _proxy_agent_config
    _webapp_audit_nginx2root
    local note
    note=$(_note)
    [[ "$note" == "info failed|nginx 1.31.8, "*"CVE-2026-123007, CVE-2026-123633."* ]]
    [[ "$note" == *"zgrep -E 'CVE-2026-(123007|123633)' /usr/share/doc/nginx/changelog.Debian.gz"* ]]
    [[ "$note" == *"|"*"turn HTTP/2 off"*"blacklist the sctp kernel module"* ]]
    [ "$(grep -o 'turn HTTP/2 off' <<< "$note" | wc -l)" -eq 1 ]
    [ "${CHECK_SCORE_CATEGORY[webapp.nginx2root]}" = "info" ]
}

@test "the listen parameter turns HTTP/2 on too; on its own it is one CVE" {
    _config 'http { server { listen 443 ssl http2; root /srv; } }'
    _webapp_audit_nginx2root
    [[ "$(_note)" == *"need: CVE-2026-123007. "* ]]
}

@test "a fixed nginx gets no note" {
    _nginx_reports 1.31.9
    _proxy_agent_config
    _webapp_audit_nginx2root
    [ -z "$(_note)" ]
}

@test "an affected nginx with none of the features gets no note" {
    _config 'http { server { listen 80; http2 off; location / { proxy_pass http://127.0.0.1:8080; } } }'
    _webapp_audit_nginx2root
    [ -z "$(_note)" ]
}

@test "HTTP/3 counts from 1.25.0, the first release with QUIC" {
    _config 'http { server { listen 443 quic reuseport; listen 443 ssl; } }'
    _webapp_audit_nginx2root
    [[ "$(_note)" == *"need: CVE-2026-121810. "*"remove quic from the listen"* ]]

    state_init
    _nginx_reports 1.24.0
    _webapp_audit_nginx2root
    [ -z "$(_note)" ]
}

@test "a subrequest needs a resolver, a variable proxy_pass and a mirror or SSI" {
    _config 'http { resolver 127.0.0.53; server { listen 80;
        location / { mirror /m; proxy_pass http://$upstream_host; } } }'
    _webapp_audit_nginx2root
    [[ "$(_note)" == *"need: CVE-2026-123634. "* ]]

    state_init
    _config 'http { resolver 127.0.0.53; server { listen 80; ssi on;
        location / { proxy_pass http://$upstream_host; } } }'
    _webapp_audit_nginx2root
    [[ "$(_note)" == *"CVE-2026-123634"* ]]

    state_init
    _config 'http { resolver 127.0.0.53; server { listen 80;
        location / { mirror off; proxy_pass http://$upstream_host; } } }'
    _webapp_audit_nginx2root
    [ -z "$(_note)" ]

    state_init
    _config 'http { server { listen 80; location / { mirror /m; proxy_pass http://$upstream_host; } } }'
    _webapp_audit_nginx2root
    [ -z "$(_note)" ]
}

@test "the mail proxy is one" {
    _config 'mail { auth_http 127.0.0.1:9000/auth; server { listen 143; protocol imap; } }'
    _webapp_audit_nginx2root
    [[ "$(_note)" == *"need: CVE-2026-113425. "*"remove the mail block"* ]]
}

@test "without a distribution changelog the version number is the answer" {
    file_package_verified() { return 1; }
    _proxy_agent_config
    _webapp_audit_nginx2root
    [[ "$(_note)" == *"no distribution changelog to check"* ]]
}

@test "the nginx half of the webapp audit asks for the note" {
    # The header check fetches each site's response; nothing listens here.
    _webapp_nginx_header_results() { :; }
    _proxy_agent_config
    _webapp_audit_nginx
    [[ "$(_note)" == "info failed|"*"CVE-2026-123007"* ]]
}
